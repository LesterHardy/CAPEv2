#!/usr/bin/env python3
"""
Example usage of the standalone network_all.py module

This script demonstrates how to use the PcapAnalyzer class
for network traffic analysis.
"""

import sys
import json
from network_all import PcapAnalyzer

def analyze_pcap_example(pcap_file):
    """Example function showing how to analyze a PCAP file"""
    
    print(f"Analyzing PCAP file: {pcap_file}")
    print("=" * 50)
    
    # Configuration options
    options = {
        "resolve_dns": False,  # Set to True for DNS resolution
        "country_lookup": False,  # Set to True if you have MaxMind DB
        "safelist_dns": True,  # Enable domain filtering
        "allowed_dns": "8.8.8.8,1.1.1.1,208.67.222.222"  # Allowed DNS servers
    }
    
    # Create analyzer instance
    analyzer = PcapAnalyzer(pcap_file, options)
    
    # Perform analysis
    results = analyzer.analyze()
    
    if not results:
        print("No results returned - check if PCAP file exists and is valid")
        return
    
    # Display summary
    print("\nAnalysis Summary:")
    print(f"  PCAP SHA256: {results.get('pcap_sha256', 'N/A')}")
    print(f"  Unique hosts: {len(results.get('hosts', []))}")
    print(f"  Unique domains: {len(results.get('domains', []))}")
    print(f"  TCP connections: {len(results.get('tcp', []))}")
    print(f"  UDP connections: {len(results.get('udp', []))}")
    print(f"  HTTP requests: {len(results.get('http', []))}")
    print(f"  DNS requests: {len(results.get('dns', []))}")
    print(f"  IRC messages: {len(results.get('irc', []))}")
    print(f"  ICMP requests: {len(results.get('icmp', []))}")
    print(f"  Dead hosts: {len(results.get('dead_hosts', []))}")
    
    # Show some sample data
    if results.get('hosts'):
        print("\nSample hosts:")
        for host in results['hosts'][:5]:  # Show first 5
            print(f"  - {host}")
    
    if results.get('domains'):
        print("\nSample domains:")
        for domain in results['domains'][:5]:  # Show first 5
            print(f"  - {domain}")
    
    if results.get('http'):
        print("\nSample HTTP requests:")
        for req in results['http'][:3]:  # Show first 3
            print(f"  - {req['method']} {req['host']}{req['uri']}")
    
    if results.get('dns'):
        print("\nSample DNS requests:")
        for req in results['dns'][:3]:  # Show first 3
            print(f"  - {req['request']} ({req['type']})")
    
    return results

def save_results_to_file(results, output_file):
    """Save analysis results to JSON file"""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to: {output_file}")
    except Exception as e:
        print(f"Error saving results: {e}")

def main():
    """Main function for command line usage"""
    if len(sys.argv) < 2:
        print("Usage: python example_usage.py <pcap_file> [output_file]")
        print("\nExample:")
        print("  python example_usage.py capture.pcap")
        print("  python example_usage.py capture.pcap results.json")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Analyze the PCAP
    results = analyze_pcap_example(pcap_file)
    
    # Save results if output file specified
    if output_file and results:
        save_results_to_file(results, output_file)
    
    print("\nAnalysis complete!")

if __name__ == "__main__":
    main()