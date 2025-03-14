#!/usr/bin/env python3
import lief
import subprocess
import re
import socket
import base64
import sys

# List of dangerous functions to flag.
DANGEROUS_FUNCTIONS = [
    "strcpy", "strcat", "sprintf", "gets", "system", "exec", "popen"
]

def load_binary(binary_path):
    """
    Parse the binary using LIEF.
    """
    binary = lief.parse(binary_path)
    if not binary:
        print(f"[-] Could not parse binary: {binary_path}")
        sys.exit(1)
    return binary

def disassemble_with_objdump(binary_path):
    """
    Use objdump to get a disassembled version of the binary.
    """
    try:
        result = subprocess.run(["objdump", "-d", binary_path],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                                check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Error disassembling binary: {e.stderr}")
        sys.exit(1)

def check_for_dangerous_functions(disassembly):
    """
    Look for dangerous functions in the disassembly.
    """
    found = []
    for func in DANGEROUS_FUNCTIONS:
        if func in disassembly:
            found.append(func)
    return found

def check_for_encoded_stuff(binary_path):
    """
    Read the binary as raw data and use a regular expression
    to search for potential Base64 encoded strings.
    """
    with open(binary_path, "rb") as f:
        data = f.read()

    # This regex searches for a long sequence of Base64 characters
    base64_candidates = re.findall(b'([A-Za-z0-9+/]{20,}={0,2})', data)
    return base64_candidates

def extract_ips(disassembly):
    """
    Use a regex to extract IP addresses from the disassembly text.
    """
    ip_regex = re.compile(r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)')
    ips = ip_regex.findall(disassembly)
    return ips

def dns_lookup(ip):
    """
    Perform a reverse DNS lookup on the given IP address.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None

def analyze(binary_path):
    print(f"[*] Analyzing binary: {binary_path}\n")

    # Load binary with LIEF (for further analysis if needed)
    binary = load_binary(binary_path)
    print(f"[+] Loaded binary: {binary.name}")

    # Disassemble using objdump
    disassembly = disassemble_with_objdump(binary_path)
    
    # Check for dangerous function calls
    dangerous = check_for_dangerous_functions(disassembly)
    if dangerous:
        print("\n[!] Dangerous functions found:")
        for func in dangerous:
            print(f"  - {func}")
    else:
        print("\n[+] No dangerous functions detected.")

    # Check for encoded content in the binary
    encoded = check_for_encoded_stuff(binary_path)
    if encoded:
        print("\n[!] Potential encoded content found:")
        for candidate in encoded:
            # Attempt to decode and show a snippet
            try:
                decoded = base64.b64decode(candidate)
                snippet = decoded[:30]
                print(f"  - Candidate: {candidate.decode('utf-8', errors='ignore')[:30]}... decodes to: {snippet} ...")
            except Exception:
                print(f"  - Candidate: {candidate.decode('utf-8', errors='ignore')} (unable to decode)")
    else:
        print("\n[+] No encoded content detected.")

    # Look for IP addresses in the disassembly
    ips = extract_ips(disassembly)
    if ips:
        print("\n[!] IP addresses found:")
        for ip in set(ips):
            hostname = dns_lookup(ip)
            if hostname:
                print(f"  - {ip} resolves to: {hostname}")
            else:
                print(f"  - {ip} has no reverse DNS entry")
    else:
        print("\n[+] No IP addresses found in disassembly.")

    # Placeholder for additional malware checks
    print("\n[+] Additional malware checks can be implemented here.")
    print("\n[*] Analysis complete.")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python malware_analyzer.py <binary_file>")
        sys.exit(1)
    binary_file = sys.argv[1]
    analyze(binary_file)
