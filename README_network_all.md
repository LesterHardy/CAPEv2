# Enhanced Network PCAP Analyzer with Malware Detection

This is an enhanced standalone network PCAP analysis module extracted and consolidated from CAPEv2. It combines comprehensive network traffic analysis with advanced malware detection capabilities, all in a single portable file.

## New in Version 2.0

- **Advanced Malware Detection**: Network-based malware family identification (CobaltStrike, Emotet, TrickBot, QakBot)
- **Threat Intelligence Integration**: Built-in IOC detection and threat scoring
- **DNS Tunneling Detection**: Entropy analysis and pattern matching for DNS tunneling
- **C2 Beaconing Detection**: Automated detection of command and control communication patterns
- **Behavioral Analysis**: Suspicious network activity identification
- **Enhanced Output Format**: Comprehensive JSON output with malware analysis results

## Features

### Network Analysis (Original Features)
- **HTTP Traffic Analysis**: Extract and analyze HTTP requests, headers, and metadata
- **DNS Analysis**: Parse DNS queries and responses, track unique domains
- **TCP/UDP Connection Tracking**: Monitor network connections and flows
- **ICMP Analysis**: Analyze ICMP packets and responses
- **IRC Detection**: Identify and parse IRC protocol messages
- **TLS/SSL Identification**: Detect and analyze encrypted connections
- **Host Enumeration**: Discover and track unique hosts with optional GeoIP lookup
- **Domain Filtering**: Built-in safelist for common legitimate domains
- **PCAP Sorting**: Utilities to sort PCAP files by network flows

### Malware Analysis (New Features)
- **Malware Family Detection**: Network-based identification of known malware families:
  - CobaltStrike beacon detection via user agents and URI patterns
  - Emotet communication pattern recognition
  - TrickBot network behavior analysis
  - QakBot traffic identification
- **Threat Intelligence**: Built-in threat feeds and IOC matching:
  - Known malicious domains and IP ranges
  - Suspicious TLD monitoring (.tk, .ml, .ga, etc.)
  - C2 communication pattern detection
- **DNS Tunneling Detection**: Advanced analysis for DNS-based data exfiltration:
  - Shannon entropy calculation for encoded data detection
  - Suspicious query type analysis (TXT, MX, NULL records)
  - Base64 encoding pattern recognition
  - Excessive subdomain monitoring
- **C2 Beaconing Analysis**: Automated detection of command and control patterns:
  - Regular interval communication detection
  - Jitter tolerance analysis
  - Statistical beaconing identification
- **Behavioral Analysis**: Network anomaly detection:
  - Port scanning identification
  - Protocol anomaly detection (HTTP on non-standard ports)
  - Excessive DNS query monitoring
  - Suspicious data exfiltration patterns
- **Threat Scoring**: Comprehensive risk assessment:
  - Weighted severity scoring system
  - Risk level classification (MINIMAL, LOW, MEDIUM, HIGH, CRITICAL)
  - Detection count and type analysis

## Dependencies

Required dependencies:
- `dpkt` - Packet parsing library
- `dnspython` - DNS resolution (optional but recommended)

Optional dependencies:
- `maxminddb` - For GeoIP country lookup
- `re2` - Faster regex processing (falls back to standard `re`)

Install dependencies:
```bash
pip install dpkt dnspython maxminddb
```

## Usage

### As a Python Module

```python
from network_all import PcapAnalyzer

# Basic usage
analyzer = PcapAnalyzer("capture.pcap")
results = analyzer.analyze()

# Access results
print("HTTP requests:", len(results['http']))
print("DNS requests:", len(results['dns']))
print("Unique hosts:", len(results['hosts']))
print("TCP connections:", len(results['tcp']))

# With options
options = {
    "resolve_dns": True,
    "country_lookup": True,
    "maxmind_db_path": "/path/to/GeoLite2-Country.mmdb",
    "safelist_dns": True,
    "allowed_dns": "8.8.8.8,1.1.1.1"
}
analyzer = PcapAnalyzer("capture.pcap", options)
results = analyzer.analyze()
```

### Command Line Usage

```bash
# Basic analysis with malware detection
python network_all.py capture.pcap

# Save results to JSON file
python network_all.py capture.pcap -o analysis_results.json

# Enable DNS resolution and GeoIP lookup
python network_all.py capture.pcap --resolve-dns --country-lookup --maxmind-db GeoLite2-Country.mmdb

# Show only malware detections and threat intelligence
python network_all.py capture.pcap --threat-only -o threats.json

# Disable malware detection (original functionality only)
python network_all.py capture.pcap --disable-malware-detection

# Enable DNS safelisting with specific DNS servers
python network_all.py capture.pcap --safelist-dns --allowed-dns "8.8.8.8,1.1.1.1"

# Sort PCAP file by flows
python network_all.py capture.pcap --sort-pcap sorted_capture.pcap

# Verbose logging
python network_all.py capture.pcap --verbose
```

### Enhanced Output Example

```python
from network_all import PcapAnalyzer

# Full analysis with malware detection
analyzer = PcapAnalyzer("malware_traffic.pcap")
results = analyzer.analyze()

# Access enhanced results
print("Threat Score:", results['malware_analysis']['threat_score']['normalized_score'])
print("Risk Level:", results['malware_analysis']['threat_score']['risk_level'])
print("Malware Families:", results['malware_analysis']['malware_families'])
print("IOCs Found:", len(results['threat_intelligence']['iocs']))

# Disable malware detection for performance
analyzer = PcapAnalyzer("large_traffic.pcap", {"enable_malware_detection": False})
results = analyzer.analyze()
```

## Enhanced Output Format

The analyzer returns a comprehensive dictionary with network analysis and malware detection results:

```json
{
  "pcap_sha256": "hash_of_pcap_file",
  "analysis_timestamp": "2024-01-15T10:30:00",
  "analyzer_version": "2.0",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "country_name": "us",
      "asn": "AS12345",
      "as_name": "Example ISP"
    }
  ],
  "domains": ["example.com", "google.com"],
  "tcp": [
    {
      "src": "192.168.1.100",
      "sport": 12345,
      "dst": "93.184.216.34",
      "dport": 80,
      "offset": 1234,
      "time": 0.123
    }
  ],
  "udp": [...],
  "icmp": [...],
  "http": [
    {
      "src": "192.168.1.100",
      "dst": "93.184.216.34",
      "dport": 80,
      "sport": 12345,
      "method": "GET",
      "host": "example.com",
      "uri": "/index.html",
      "version": "1.1",
      "user_agent": "Mozilla/5.0...",
      "timestamp": 1234567890.123,
      "data": "GET /index.html HTTP/1.1..."
    }
  ],
  "dns": [
    {
      "request": "example.com",
      "type": "A",
      "timestamp": 1234567890.123,
      "answers": [
        {"type": "A", "data": "93.184.216.34"}
      ]
    }
  ],
  "malware_analysis": {
    "threat_score": {
      "raw_score": 35,
      "normalized_score": 75.0,
      "risk_level": "HIGH",
      "detection_count": 5
    },
    "malware_families": ["CobaltStrike", "Emotet"],
    "detections": [
      {
        "type": "malware_family",
        "family": "CobaltStrike",
        "indicator": "user_agent",
        "value": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
        "severity": "high",
        "description": "User agent matches CobaltStrike malware pattern"
      },
      {
        "type": "dns_tunneling",
        "indicator": "high_entropy",
        "value": "asd8f7a9sd8f7a9sd8f.example.com",
        "severity": "medium",
        "description": "High entropy (4.2) suggests encoded data"
      }
    ],
    "detections_by_type": {
      "malware_family": [...],
      "dns_tunneling": [...],
      "behavioral": [...],
      "threat_intelligence": [...]
    },
    "detection_summary": {
      "total_detections": 5,
      "critical_detections": 1,
      "high_detections": 2,
      "medium_detections": 2,
      "low_detections": 0
    }
  },
  "threat_intelligence": {
    "malicious_domains_contacted": ["evil.tk", "bad.ml"],
    "malicious_ips_contacted": [
      {
        "ip": "185.159.158.123",
        "hostname": "",
        "country": "unknown"
      }
    ],
    "iocs": [
      {
        "type": "user_agent",
        "value": "WinHTTP Example/1.0",
        "severity": "high",
        "description": "User agent matches TrickBot pattern"
      }
    ]
  },
  "irc": [...],
  "smtp": [...],
  "dead_hosts": [
    {"ip": "192.168.1.1", "port": 80, "attempts": 5}
  ]
}
```

## Configuration Options

- `resolve_dns`: Enable reverse DNS resolution for IP addresses
- `country_lookup`: Enable GeoIP country lookup (requires MaxMind database)
- `maxmind_db_path`: Path to MaxMind GeoIP database file
- `safelist_dns`: Enable DNS request filtering based on allowed servers
- `allowed_dns`: Comma-separated list of allowed DNS server IPs

## GeoIP Setup

To enable country lookup:

1. Download MaxMind GeoLite2 database:
   ```bash
   wget https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_KEY&suffix=tar.gz
   ```

2. Extract and specify path:
   ```python
   options = {
       "country_lookup": True,
       "maxmind_db_path": "/path/to/GeoLite2-Country.mmdb"
   }
   ```

## Differences from Original CAPEv2 Module

This enhanced standalone version:
- **Removes CAPEv2-specific dependencies** and configuration system
- **Adds comprehensive malware detection** without external YARA or Suricata dependencies
- **Includes network-based threat intelligence** for IOC detection
- **Provides simplified configuration interface** with enhanced options
- **Adds command-line interface** for standalone usage with malware analysis options
- **Enhances output format** with detailed malware analysis results
- **Implements self-contained detection logic** based on CAPEv2's malware signatures
- **Includes behavioral analysis** for suspicious network patterns
- **Adds threat scoring system** for risk assessment

## Malware Detection Capabilities

### Supported Malware Families
- **CobaltStrike**: Beacon detection via user agents, URI patterns, and beaconing behavior
- **Emotet**: Domain patterns, user agents, and communication characteristics
- **TrickBot**: URI patterns and user agent identification
- **QakBot**: Network communication pattern recognition

### Detection Types
- **Malware Family Detection**: Known malware patterns and signatures
- **DNS Tunneling**: Entropy analysis, query type monitoring, base64 detection
- **C2 Beaconing**: Regular interval communication pattern analysis
- **Threat Intelligence**: IOC matching against known bad domains/IPs
- **Behavioral Analysis**: Anomalous network activity detection
- **Protocol Anomalies**: Non-standard protocol usage detection

### Threat Intelligence Sources
- Built-in malicious domain lists
- Suspicious TLD monitoring
- Known malicious IP ranges
- C2 communication pattern database
- DNS tunneling indicators

## Performance Considerations

- **Malware detection can be disabled** for performance-critical analysis
- **Large PCAP files** are processed incrementally with progress logging
- **Optional features** can be disabled to improve performance
- **Memory usage optimized** for streaming processing
- **Threat-only mode** available for focused malware analysis

## Examples

See `test_network_all.py` for working examples and test cases.

## License

This module is extracted from CAPEv2 and maintains the original license terms.