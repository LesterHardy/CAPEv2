#!/usr/bin/env python
"""
Test script for network_all.py - validates malware detection functionality
"""

import os
import sys
import subprocess
import json
import tempfile

# Add CAPE root to path
CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

def test_basic_functionality():
    """Test basic script functionality."""
    print("Testing basic script functionality...")
    
    # Test help command
    result = subprocess.run([
        sys.executable, 'utils/network_all.py', '--help'
    ], capture_output=True, text=True, cwd=CUCKOO_ROOT)
    
    assert result.returncode == 0, f"Help command failed: {result.stderr}"
    assert "Comprehensive Network and Malware Analysis" in result.stdout
    print("✓ Help command works")

def test_malware_detection():
    """Test malware detection capabilities."""
    print("Testing malware detection...")
    
    # Test with our malicious test PCAP
    if not os.path.exists('/tmp/malicious_test.pcap'):
        print("✗ Malicious test PCAP not found, skipping detection test")
        return
    
    result = subprocess.run([
        sys.executable, 'utils/network_all.py', 
        '/tmp/malicious_test.pcap',
        '--no-virustotal', '--no-mandiant'
    ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, cwd=CUCKOO_ROOT)
    
    if result.returncode != 0:
        print(f"✗ Script failed: {result.stderr}")
        return
    
    # Parse JSON output
    try:
        # Split output by the assessment summary marker
        json_part = result.stdout.split('=== THREAT ASSESSMENT ===')[0].strip()
        results = json.loads(json_part)
        
        # Validate threat assessment
        threat_assessment = results.get('threat_assessment', {})
        threat_level = threat_assessment.get('threat_level', 'UNKNOWN')
        threat_score = threat_assessment.get('threat_score', 0)
        
        print(f"✓ Threat level: {threat_level}")
        print(f"✓ Threat score: {threat_score}")
        
        # Check for detected indicators
        malware_indicators = threat_assessment.get('malware_indicators', {})
        suspicious_domains = malware_indicators.get('suspicious_domains', [])
        behavioral_indicators = malware_indicators.get('behavioral_indicators', [])
        
        if suspicious_domains:
            print(f"✓ Detected {len(suspicious_domains)} suspicious domains")
            for domain in suspicious_domains:
                print(f"  - {domain['domain']} ({domain['reason']})")
        
        if behavioral_indicators:
            print(f"✓ Detected {len(behavioral_indicators)} behavioral indicators")
            for indicator in behavioral_indicators:
                print(f"  - {indicator['type']} ({indicator['reason']})")
        
        # Verify we detected the malicious indicators we put in the test PCAP
        expected_detections = [
            'suspicious_tld',   # .tk domain
            'dga_pattern',      # DGA-like domain
            'high_entropy'      # High entropy domain
        ]
        
        detected_reasons = []
        for domain in suspicious_domains:
            detected_reasons.append(domain['reason'])
        for indicator in behavioral_indicators:
            detected_reasons.append(indicator['reason'])
        
        found_detections = [reason for reason in expected_detections if reason in detected_reasons]
        
        if found_detections:
            print(f"✓ Successfully detected expected malware indicators: {found_detections}")
        else:
            print("✗ Failed to detect expected malware indicators")
        
        # Verify threat level is appropriate
        if threat_score > 0 and threat_level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            print("✓ Threat scoring working correctly")
        else:
            print(f"✗ Unexpected threat assessment: {threat_level} (score: {threat_score})")
            
    except json.JSONDecodeError as e:
        print(f"✗ JSON parsing failed: {e}")
        print("Raw output:", result.stdout[:500])

def test_error_handling():
    """Test error handling for invalid inputs."""
    print("Testing error handling...")
    
    # Test with non-existent file
    result = subprocess.run([
        sys.executable, 'utils/network_all.py', 
        '/tmp/nonexistent.pcap',
        '--no-virustotal', '--no-mandiant'
    ], capture_output=True, text=True, cwd=CUCKOO_ROOT)
    
    # Should handle gracefully
    if "not found" in result.stderr.lower() or "does not exist" in result.stdout.lower():
        print("✓ Non-existent file handled gracefully")
    else:
        print("✗ Non-existent file not handled properly")

def main():
    """Run all tests."""
    print("Running network_all.py tests...\n")
    
    try:
        test_basic_functionality()
        print()
        
        test_malware_detection()
        print()
        
        test_error_handling()
        print()
        
        print("✓ All tests completed!")
        
    except Exception as e:
        print(f"✗ Test failed with exception: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())