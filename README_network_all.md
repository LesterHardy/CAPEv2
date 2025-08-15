# Network PCAP Analyzer - Standalone Module

This is a standalone network PCAP analysis module extracted and consolidated from CAPEv2. It provides comprehensive network traffic analysis capabilities for tcpdump-exported network packets.

## Features

- **HTTP Traffic Analysis**: Extract and analyze HTTP requests, headers, and metadata
- **DNS Analysis**: Parse DNS queries and responses, track unique domains
- **TCP/UDP Connection Tracking**: Monitor network connections and flows
- **ICMP Analysis**: Analyze ICMP packets and responses
- **IRC Detection**: Identify and parse IRC protocol messages
- **TLS/SSL Identification**: Detect and analyze encrypted connections
- **Host Enumeration**: Discover and track unique hosts with optional GeoIP lookup
- **Domain Filtering**: Built-in safelist for common legitimate domains
- **PCAP Sorting**: Utilities to sort PCAP files by network flows

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
# Basic analysis
python network_all.py capture.pcap

# Save results to JSON file
python network_all.py capture.pcap -o analysis_results.json

# Enable DNS resolution and GeoIP lookup
python network_all.py capture.pcap --resolve-dns --country-lookup --maxmind-db GeoLite2-Country.mmdb

# Enable DNS safelisting with specific DNS servers
python network_all.py capture.pcap --safelist-dns --allowed-dns "8.8.8.8,1.1.1.1"

# Sort PCAP file by flows
python network_all.py capture.pcap --sort-pcap sorted_capture.pcap

# Verbose logging
python network_all.py capture.pcap --verbose
```

## Output Format

The analyzer returns a dictionary with the following structure:

```json
{
  "pcap_sha256": "hash_of_pcap_file",
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

This standalone version:
- Removes CAPEv2-specific dependencies and configuration system
- Simplifies the Processing base class
- Includes all necessary utility functions inline
- Provides a simpler configuration interface
- Adds command-line interface for standalone usage
- Focuses on core PCAP analysis without malware-specific features

## Error Handling

The module handles various error conditions gracefully:
- Missing or corrupted PCAP files
- Unsupported PCAP formats
- Network parsing errors
- DNS resolution timeouts
- Missing optional dependencies

## Performance Considerations

- Large PCAP files are processed incrementally
- Progress logging for files with many packets
- Optional features can be disabled to improve performance
- Memory usage is optimized for streaming processing

## Examples

See `test_network_all.py` for working examples and test cases.

## License

This module is extracted from CAPEv2 and maintains the original license terms.