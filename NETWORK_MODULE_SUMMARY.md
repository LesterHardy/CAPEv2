# 🌐 Network PCAP Analyzer - Standalone Module

**A consolidated, portable network analysis module extracted from CAPEv2**

## 📁 Files Included

- **`network_all.py`** - Main standalone module (all dependencies consolidated)
- **`README_network_all.md`** - Comprehensive documentation
- **`example_usage.py`** - Example usage script with demonstrations
- **`test_network_all.py`** - Test suite validating functionality

## 🚀 Quick Start

```python
from network_all import PcapAnalyzer

# Analyze a PCAP file
analyzer = PcapAnalyzer("your_capture.pcap")
results = analyzer.analyze()

# Access results
print(f"Found {len(results['http'])} HTTP requests")
print(f"Found {len(results['dns'])} DNS queries")
print(f"Found {len(results['hosts'])} unique hosts")
```

## 🎯 Key Features

- ✅ **Zero CAPEv2 dependencies** - All utilities consolidated into single file
- ✅ **HTTP/HTTPS analysis** - Extract requests, headers, user agents
- ✅ **DNS analysis** - Parse queries, responses, track domains
- ✅ **Network flow tracking** - TCP/UDP connections with timing
- ✅ **Protocol detection** - IRC, SMTP, ICMP analysis
- ✅ **Host enumeration** - Optional GeoIP and DNS resolution
- ✅ **Command line interface** - Ready for shell scripting
- ✅ **JSON output** - Structured results for further processing
- ✅ **PCAP sorting** - Flow-based packet sorting utilities

## 📦 Installation

```bash
# Required dependencies
pip install dpkt dnspython

# Optional (for GeoIP lookup)
pip install maxminddb
```

## 🎮 Usage Examples

### Command Line
```bash
# Basic analysis
python network_all.py capture.pcap

# With DNS resolution and GeoIP
python network_all.py capture.pcap --resolve-dns --country-lookup

# Save to JSON
python network_all.py capture.pcap -o results.json
```

### Python Module
```python
# With advanced options
options = {
    "resolve_dns": True,
    "country_lookup": True,
    "maxmind_db_path": "/path/to/GeoLite2-Country.mmdb",
    "safelist_dns": True
}
analyzer = PcapAnalyzer("capture.pcap", options)
results = analyzer.analyze()
```

## 📊 Sample Output

```json
{
  "pcap_sha256": "abc123...",
  "hosts": [{"ip": "8.8.8.8", "country_name": "us"}],
  "http": [{"method": "GET", "host": "example.com", "uri": "/"}],
  "dns": [{"request": "example.com", "type": "A", "answers": [...]}],
  "tcp": [{"src": "192.168.1.1", "dst": "8.8.8.8", "dport": 53}]
}
```

## 🔄 Migration from CAPEv2

This module provides the same core functionality as CAPEv2's `modules/processing/network.py` but:

- **Removes** CAPEv2-specific configuration and dependencies
- **Simplifies** the interface for standalone usage  
- **Consolidates** all utility functions into a single file
- **Adds** command-line interface for easy integration

## ✅ Tested & Validated

- All core functionality tested and working
- Import validation passed
- Utility functions verified
- Command line interface functional
- Cross-platform compatibility

---

**Ready for integration into any Python project for network traffic analysis! 🎉**