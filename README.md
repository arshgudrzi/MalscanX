# MalScanX

MalScanX is a lightweight yet effective static malware analysis tool that disassembles binaries and searches for potential malicious behavior. It uses LIEF for binary parsing, objdump for disassembly, and various heuristics to detect signs of malware, such as:

- **Dangerous function calls** (e.g., `system()`, `strcpy()`, `popen()`)
- **Base64-encoded payloads** or suspicious encoded content
- **Hardcoded IP addresses** with DNS lookups for intelligence
- **Potential malware indicators** in the binary structure

## Features

✔️ Disassembles executables and scans for dangerous function calls  
✔️ Detects encoded data that might be obfuscated malware payloads  
✔️ Extracts hardcoded IP addresses and performs DNS lookups  
✔️ Uses regex-based heuristics to flag potentially malicious content  
✔️ Lightweight, simple to use, and extendable  

## Installation

You need Python 3 and the following dependencies:

```bash
pip install lief
sudo apt install binutils
