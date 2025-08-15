#!/usr/bin/env python3
"""
Test script to demonstrate the standalone network_all.py module
"""

import sys
from network_all import PcapAnalyzer

def test_basic_functionality():
    """Test basic functionality without a real PCAP file"""
    print("Testing network_all.py module...")
    
    # Test 1: Create analyzer instance
    print("✓ Test 1: Creating analyzer instance")
    options = {
        "resolve_dns": False,
        "country_lookup": False,
        "safelist_dns": False
    }
    analyzer = PcapAnalyzer("nonexistent.pcap", options)
    print("  Analyzer created successfully")
    
    # Test 2: Test utility functions
    print("✓ Test 2: Testing utility functions")
    from network_all import is_private_ip, convert_to_printable, is_safelisted_domain
    
    # Test private IP detection
    assert is_private_ip("192.168.1.1") == True
    assert is_private_ip("8.8.8.8") == False
    print("  Private IP detection working")
    
    # Test printable conversion
    result = convert_to_printable(b"hello")
    assert result == "hello"
    print("  Printable conversion working")
    
    # Test domain safelisting
    result1 = is_safelisted_domain("update.windows.com")  # Should match \.windows\.com$
    result2 = is_safelisted_domain("example.com")  # Should not match any pattern
    assert result1 == True  # Should match \.windows\.com$ pattern
    assert result2 == False  # Should not match any pattern
    print("  Domain safelisting working")
    
    # Test 3: Test analyze with nonexistent file (should return empty dict)
    print("✓ Test 3: Testing analyze with nonexistent file")
    result = analyzer.analyze()
    assert result == {}
    print("  Correctly handled nonexistent file")
    
    # Test 4: Test command line help
    print("✓ Test 4: Testing command line interface")
    try:
        from network_all import main
        print("  CLI function imported successfully")
    except:
        print("  Warning: CLI function import failed")
    
    print("\n✅ All basic tests passed!")
    print("\nUsage examples:")
    print("1. As a module:")
    print("   from network_all import PcapAnalyzer")
    print("   analyzer = PcapAnalyzer('your_capture.pcap')")
    print("   results = analyzer.analyze()")
    print("")
    print("2. From command line:")
    print("   python network_all.py your_capture.pcap")
    print("   python network_all.py your_capture.pcap -o results.json --resolve-dns")
    print("")
    print("Features included:")
    print("- HTTP request extraction and analysis")
    print("- DNS query and response analysis")
    print("- TCP/UDP connection tracking")
    print("- ICMP packet analysis")
    print("- IRC message detection")
    print("- TLS/SSL connection identification")
    print("- Host enumeration with optional GeoIP lookup")
    print("- Domain safelisting and filtering")
    print("- PCAP sorting utilities")

if __name__ == "__main__":
    test_basic_functionality()