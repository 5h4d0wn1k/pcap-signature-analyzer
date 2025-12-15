"""
Simple PCAP signature checks (lab/demo).
Requires scapy. If unavailable, exits with instruction.
Detections:
- SYN flood heuristic: high SYN with low SYN/ACK ratio per src IP.
- DNS long/TXT queries (possible exfil).
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter


def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP signature checks (lab/demo).")
    parser.add_argument("--pcap", required=True, help="PCAP file path.")
    parser.add_argument("--syn-threshold", type=int, default=200, help="SYN count threshold.")
    args = parser.parse_args()

    try:
        from scapy.all import DNS, DNSQR, IP, TCP, rdpcap  # type: ignore
    except Exception:
        print("scapy not installed. pip install scapy", file=sys.stderr)
        sys.exit(1)

    syn_counts: Counter[str] = Counter()
    synack_counts: Counter[str] = Counter()
    dns_suspect: list[str] = []

    packets = rdpcap(args.pcap)
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            flags = pkt[TCP].flags
            src = pkt[IP].src
            if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
                syn_counts[src] += 1
            if flags & 0x12 == 0x12:  # SYN+ACK
                synack_counts[src] += 1
        if DNS in pkt and pkt[DNS].qd and isinstance(pkt[DNS].qd, DNSQR):
            qname = pkt[DNS].qd.qname.decode(errors="ignore")
            if len(qname) > 80 or pkt[DNS].qd.qtype == 16:  # TXT
                dns_suspect.append(qname)

    syn_findings = [
        {"src": src, "syn": syn_counts[src], "synack": synack_counts.get(src, 0)}
        for src, count in syn_counts.items()
        if count >= args.syn_threshold and synack_counts.get(src, 0) < count // 5
    ]

    report = {
        "syn_flood_suspects": syn_findings,
        "dns_long_or_txt_queries": dns_suspect[:50],
    }
    print(report)


if __name__ == "__main__":
    main()
