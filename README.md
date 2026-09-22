> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# PCAP Signature Analyzer

Signature-based **network traffic analysis** for captured PCAP files: detects
SYN flood (DDoS) and DNS-exfiltration patterns for **network security**,
**incident response**, and educational labs.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/pcap-signature-analyzer)](https://github.com/5h4d0wn1k/pcap-signature-analyzer)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/pcap-signature-analyzer)](https://github.com/5h4d0wn1k/pcap-signature-analyzer/issues)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/pcap-signature-analyzer)](https://github.com/5h4d0wn1k/pcap-signature-analyzer)
[![Version](https://img.shields.io/badge/version-1.1.0-blue)](VERSION)

## Why

Packet captures are where attacks leave their footprint — and where defenders
first look during an incident. Two signature patterns cover a remarkable share
of everyday suspicious traffic: the SYN flood (a burst of connection attempts
with almost no completed handshakes) and DNS exfiltration (data tunnelled out
inside unusually long queries or TXT records). PCAP Signature Analyzer is a
small, focused, signature-based detector that flags exactly those two patterns
in a PCAP file, with a configurable SYN threshold and documented detection
heuristics (SYN/ACK ratio < 20%, query length > 80 characters, type 16 TXT
records). It is intended for authorized interception analysis on captures you
own, incident-response triage, and security education.

## Features

- **SYN flood detection** — flags source IPs with high SYN counts and a low
  SYN/ACK ratio (configurable threshold, default 200)
- **DNS exfiltration detection** — catches long queries (>80 chars) and TXT
  record queries (type 16)
- **Signature-based scoring** — deterministic, explainable detections
- **JSON output** — structured `syn_flood_suspects` and
  `dns_long_or_txt_queries` result object

## Quickstart

Requirements: Python 3.8+, `scapy`.

```bash
pip install "scapy>=2.5.0"

# Analyze a PCAP file
python pcap_signatures.py --pcap capture.pcap

# Custom SYN flood threshold
python pcap_signatures.py --pcap capture.pcap --syn-threshold 500
```

CLI options: `--pcap` (required path to the PCAP file) and `--syn-threshold`
(SYN count threshold for flood detection, default 200).

## Example output

```json
{
  "syn_flood_suspects": [{ "src": "192.168.1.100", "syn": 500, "synack": 10 }],
  "dns_long_or_txt_queries": ["very-long-suspicious-domain.example.com"]
}
```

## Project structure

- `pcap_signatures.py` — CLI entry point and detection engine
- `CHANGELOG.md` — version history
- `VERSION` — current release (1.1.0)

## Use cases

- Network security monitoring and incident-response triage
- Threat detection for authorized captures
- Classroom material for learning about network attacks

## Legal & authorized use

For **educational and authorized security analysis only** — analyze only PCAP
files you own or have explicit authorization to inspect. See
[ETHICS.md](ETHICS.md), [SCOPE.md](SCOPE.md), and [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).