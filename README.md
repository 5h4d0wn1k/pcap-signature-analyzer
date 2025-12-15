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

## Legal Disclaimer

⚠️ **IMPORTANT**: This tool is for authorized security analysis and educational purposes only.

- Only analyze PCAP files you own or have explicit written authorization to analyze
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is for educational purposes only. Use responsibly and ethically.

---

**Remember**: Only analyze PCAP files you own or have explicit authorization to analyze!
