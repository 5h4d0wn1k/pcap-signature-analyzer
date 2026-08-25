# PCAP Signature Analyzer

⚠️ **EDUCATIONAL PURPOSE ONLY** - This tool is designed for authorized security analysis and educational purposes. Only use on PCAP files you own or have explicit written authorization to analyze.

## Overview

A network traffic analyzer that detects suspicious patterns in PCAP files including SYN flood attacks and DNS exfiltration attempts. Uses signature-based detection to identify common attack patterns.

## Features

- **SYN Flood Detection**: Identifies potential SYN flood attacks
- **DNS Exfiltration Detection**: Detects suspicious DNS queries (long queries, TXT records)
- **Traffic Analysis**: Analyzes network traffic patterns
- **Signature-Based**: Uses known attack signatures for detection

## Installation

### Requirements

- Python 3.8+
- scapy library

### Setup

```bash
# Clone the repository
git clone https://github.com/5h4d0wn1k/pcap-signature-analyzer.git
cd pcap-signature-analyzer

# Install dependencies
pip install scapy

# Verify installation
python pcap_signatures.py --help
```

## Usage

### Basic Usage

```bash
# Analyze PCAP file
python pcap_signatures.py --pcap capture.pcap
```

### Custom Threshold

```bash
# Set custom SYN flood threshold
python pcap_signatures.py \
  --pcap capture.pcap \
  --syn-threshold 500
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--pcap` | Path to PCAP file (required) | - |
| `--syn-threshold` | SYN count threshold for flood detection | 200 |

## Detected Patterns

### 1. SYN Flood Attacks

Detects potential SYN flood (DDoS) attacks:
- **Pattern**: High number of SYN packets with low SYN/ACK ratio
- **Threshold**: Configurable (default: 200 SYN packets)
- **Ratio**: SYN/ACK ratio < 20% indicates potential flood
- **Severity**: High
- **Action**: Investigate source IPs, implement rate limiting

### 2. DNS Exfiltration

Detects potential DNS-based data exfiltration:
- **Pattern**: Unusually long DNS queries or TXT record queries
- **Threshold**: Query length > 80 characters
- **Type**: TXT record queries (type 16)
- **Severity**: Medium-High
- **Action**: Investigate DNS queries, monitor DNS traffic

## Output Format

```python
{
  "syn_flood_suspects": [
    {
      "src": "192.168.1.100",
      "syn": 500,
      "synack": 10
    }
  ],
  "dns_long_or_txt_queries": [
    "very-long-suspicious-domain-name.example.com",
    "data-exfiltration-domain.txt.example.com"
  ]
}
```

## Examples

### Example 1: Basic Analysis

```bash
# Analyze PCAP file
python pcap_signatures.py --pcap network_capture.pcap
```

### Example 2: Custom Threshold

```bash
# Use higher threshold for SYN flood detection
python pcap_signatures.py \
  --pcap network_capture.pcap \
  --syn-threshold 1000
```

## Use Cases

- **Network Security**: Detect attacks in network traffic
- **Incident Response**: Analyze captured network traffic
- **Threat Detection**: Identify suspicious patterns
- **Educational Purposes**: Learn about network attacks

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## ⚠️ Legal Disclaimer

### Educational Purpose Only
This tool is provided strictly for **educational purposes** and **authorized security testing** only. It is intended to help security professionals and students learn about security concepts in controlled environments.

### Authorized Use Only
- You must have **explicit written authorization** before testing any system you do not own
- Unauthorized access to computer systems is **illegal** and punishable under laws including but not limited to the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and similar legislation worldwide
- Only use this tool on systems you own, have permission to test, or in isolated lab environments

### No Warranty
This software is provided "AS IS" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. The author makes no representations or warranties regarding the accuracy, completeness, or reliability of this software.

### Limitation of Liability
**In no event shall the author (Nikhil Nagpure) be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.**

### User Responsibility
- The user assumes **full responsibility** for any consequences resulting from the use of this tool
- The author is **not responsible** for any misuse, damage, or illegal activities performed with this software
- Users are solely responsible for ensuring compliance with all applicable local, state, national, and international laws and regulations

### Indemnification
By using this software, you agree to **indemnify, defend, and hold harmless** the author from and against any and all claims, liabilities, damages, losses, costs, and expenses (including reasonable attorneys fees) arising from or related to your use of this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, please follow responsible disclosure practices and report them to the affected parties through appropriate channels.

---

**By using this software, you acknowledge that you have read, understood, and agree to be bound by this disclaimer.**
## License

This project is for educational purposes only. Use responsibly and ethically.

---

**Remember**: Only analyze PCAP files you own or have explicit authorization to analyze!
