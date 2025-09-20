#!/usr/bin/env python3

import socket
import struct
import json
import time
import argparse
import sys
from dnslib import DNSRecord

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353

def ascii_dump(data):
    return ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data])

# Parse command-line arguments
parser = argparse.ArgumentParser(
    description="Listen for Bonjour/mDNS packets and log them in structured JSON format."
)
parser.add_argument(
    "--logfile",
    metavar="PATH",
    help="Path to log file (JSON lines). If omitted, logs to stdout."
)
parser.add_argument(
    "-q", "--quiet",
    action="store_true",
    help="Suppress stdout output; requires --logfile"
)
args = parser.parse_args()

# Validate argument combination
if args.quiet and not args.logfile:
    print("Error: --quiet requires --logfile. Otherwise, no output will be produced.", file=sys.stderr)
    sys.exit(1)

# Optional file handle
log_file = open(args.logfile, "a") if args.logfile else None
packet_count = 0

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', MDNS_PORT))

# Join multicast group
mreq = struct.pack("4sl", socket.inet_aton(MDNS_GROUP), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

if not args.quiet:
    print(f"Listening for Bonjour/mDNS packets on {MDNS_GROUP}:{MDNS_PORT}...\n")

try:
    while True:
        data, addr = sock.recvfrom(9000)
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%S%z')
        packet_count += 1

        log_entry = {
            "timestamp": timestamp,
            "source_ip": addr[0],
            "source_port": addr[1],
            "length": len(data),
            "hex": data.hex(),
            "ascii": ascii_dump(data),
            "dns": None,
            "error": None
        }

        try:
            dns = DNSRecord.parse(data)
            log_entry["dns"] = {
                "id": dns.header.id,
                "qr": dns.header.qr,
                "opcode": str(dns.header.opcode),
                "rcode": str(dns.header.rcode),
                "questions": [str(q.qname) for q in dns.questions],
                "answers": [str(a.rdata) for a in dns.rr]
            }
        except Exception as e:
            log_entry["error"] = f"DNS parse failed: {str(e)}"

        output = json.dumps(log_entry)

        if log_file:
            log_file.write(output + "\n")
            log_file.flush()

        if not args.quiet and not log_file:
            print(output)
        elif args.logfile and not args.quiet:
            print(f"Captured {packet_count} packet{'s' if packet_count > 1 else ''}...", end='\r')
except KeyboardInterrupt:
    if args.logfile and not args.quiet:
        print(f"\nStopped listening. Total packets captured: {packet_count}")
    elif not args.quiet:
        print("\nStopped listening.")
finally:
    if log_file:
        log_file.close()
