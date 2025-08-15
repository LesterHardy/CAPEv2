# network_all.py - Comprehensive Network and Malware Analysis

## Overview

`network_all.py` is a comprehensive network analysis script that combines PCAP packet analysis with advanced malware detection capabilities. It provides enhanced threat intelligence and behavioral analysis for network traffic captured in PCAP files.

## Features

### Core Functionality
- **PCAP Analysis**: Full packet capture analysis using dpkt library
- **Network Protocol Support**: TCP, UDP, DNS, HTTP analysis
- **Threat Intelligence Integration**: VirusTotal and Mandiant Intel APIs
- **Behavioral Analysis**: Pattern detection for malicious activities
- **Comprehensive Reporting**: JSON output with threat assessment

### Malware Detection Capabilities

#### Domain Analysis
- **Suspicious TLD Detection**: Identifies domains using high-risk TLDs (.tk, .ml, .ga, etc.)
- **DGA Pattern Detection**: Detects Domain Generation Algorithm patterns
- **High Entropy Domains**: Identifies randomly generated domain names
- **Homograph Attacks**: Detects IDN spoofing attempts

#### IP Address Analysis
- **Private/Public Classification**: Distinguishes between internal and external IPs
- **Suspicious IP Characteristics**: Identifies IPs with malicious indicators
- **Geolocation Analysis**: Optional country/ASN information

#### Behavioral Pattern Detection
- **C2 Beaconing**: Detects regular communication patterns indicating C&C
- **Data Exfiltration**: Identifies large outbound data transfers
- **Protocol Tunneling**: Detects suspicious protocol/port combinations

#### Threat Intelligence Integration
- **VirusTotal Integration**: Domain and IP reputation checking
- **Mandiant Intelligence**: Advanced threat actor and malware intelligence
- **Graceful Fallback**: Works without API access when configured

### Threat Assessment
- **Scoring System**: Numerical threat scoring (0-100+)
- **Risk Levels**: CLEAN, LOW, MEDIUM, HIGH, CRITICAL classifications
- **Detailed Reporting**: Comprehensive threat analysis with explanations

## Installation

### Prerequisites
```bash
# Install required Python packages
pip install dpkt
```

### Optional Dependencies
- **VirusTotal API**: Configure API key for domain/IP reputation
- **Mandiant Intel API**: Configure credentials for advanced threat intelligence
- **CAPE Network Module**: Enhanced integration with existing CAPE processing

## Usage

### Basic Usage
```bash
# Analyze a PCAP file
python utils/network_all.py /path/to/capture.pcap

# Save results to JSON file
python utils/network_all.py /path/to/capture.pcap -o results.json

# Enable verbose logging
python utils/network_all.py /path/to/capture.pcap -v
```

### Advanced Options
```bash
# Skip external API calls
python utils/network_all.py capture.pcap --no-virustotal --no-mandiant

# Comprehensive analysis with all features
python utils/network_all.py capture.pcap -v -o full_analysis.json
```

### Command Line Options
- `pcap_path`: Path to the PCAP file to analyze (required)
- `-o, --output`: Output file for results in JSON format
- `-v, --verbose`: Enable verbose logging
- `--no-virustotal`: Skip VirusTotal queries
- `--no-mandiant`: Skip Mandiant Intel queries
- `-h, --help`: Show help message

## Output Format

The script outputs comprehensive JSON results with the following structure:

```json
{
  "basic_network": {
    "domains": ["example.com", "malicious.tk"],
    "hosts": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}],
    "dns": [{"request": "example.com", "src": "...", "dst": "..."}],
    "tcp": [{"src": "...", "dst": "...", "sport": 80, "dport": 443}],
    "udp": [{"src": "...", "dst": "...", "sport": 53, "dport": 53}],
    "http": []
  },
  "threat_assessment": {
    "threat_score": 23,
    "threat_level": "MEDIUM",
    "threat_details": [
      "Suspicious domain: malicious.tk (suspicious_tld)",
      "Behavioral indicator: dga_domain (high_entropy)"
    ],
    "malware_indicators": {
      "suspicious_domains": [
        {
          "domain": "malicious.tk",
          "reason": "suspicious_tld",
          "severity": "medium"
        }
      ],
      "malicious_ips": [],
      "behavioral_indicators": [
        {
          "type": "dga_domain",
          "indicator": "malicious.tk",
          "reason": "high_entropy",
          "severity": "medium"
        }
      ],
      "threat_intel_hits": []
    }
  }
}
```

## Configuration

### VirusTotal Integration
Configure VirusTotal API access in CAPE's configuration:
```ini
[virustotal]
key = your_api_key_here
do_file_lookup = yes
do_url_lookup = yes
```

### Mandiant Intelligence Integration
Configure Mandiant Intel API access:
```ini
[mandiant_intel]
api_access = your_access_key
api_secret = your_secret_key
```

## Examples

### Analyzing Malicious Traffic
```bash
# Analyze suspected malware communication
python utils/network_all.py malware_traffic.pcap -v

# Sample output:
# === THREAT ASSESSMENT ===
# Threat Level: HIGH
# Threat Score: 45
# 
# Threats Detected:
#   - Suspicious domain: abc123def456.tk (dga_pattern)
#   - Behavioral indicator: c2_beaconing (regular_intervals)
#   - Threat intel hit: 1.2.3.4 (VT: 8/65 detections)
```

### Batch Analysis
```bash
# Analyze multiple PCAP files
for pcap in *.pcap; do
    echo "Analyzing $pcap..."
    python utils/network_all.py "$pcap" -o "${pcap%.pcap}_analysis.json"
done
```

## Integration with CAPE

The script is designed to integrate seamlessly with the CAPE malware analysis platform:

1. **Processing Module**: Can be used as a standalone processor or integrated into CAPE's processing pipeline
2. **Existing Components**: Leverages CAPE's VirusTotal and Mandiant integrations when available
3. **Configuration**: Uses CAPE's configuration system for API credentials
4. **Fallback Mode**: Works independently when CAPE components are unavailable

## Testing

Run the included test suite to validate functionality:

```bash
python tests/test_network_all.py
```

The tests verify:
- Basic script functionality
- Malware detection capabilities
- Error handling for invalid inputs
- JSON output parsing
- Threat assessment accuracy

## Troubleshooting

### Common Issues

1. **Missing dpkt library**
   ```bash
   pip install dpkt
   ```

2. **CAPE modules not found**
   - Script will work with reduced functionality
   - Install CAPE dependencies or run in standalone mode

3. **API rate limiting**
   - Use `--no-virustotal` and `--no-mandiant` for offline analysis
   - Configure API keys for higher rate limits

4. **Large PCAP files**
   - Script processes files efficiently but very large files may take time
   - Consider splitting large captures into smaller files

### Debug Mode
```bash
# Enable maximum verbosity for troubleshooting
python utils/network_all.py capture.pcap -v
```

## Contributing

When contributing to the script:
1. Follow existing code style and patterns
2. Add tests for new detection capabilities
3. Update documentation for new features
4. Ensure compatibility with CAPE ecosystem

## License

This script is part of the CAPEv2 project and follows the same licensing terms.