#!/usr/bin/env python3

import socket
import struct
import json
import time
import argparse
from dnslib import DNSRecord

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353

def ascii_dump(data):
    return ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data])

# Parse command-line arguments
parser = argparse.ArgumentParser(description="mDNS listener with structured logging")
parser.add_argument("--logfile", help="Path to log file (JSON lines). If omitted, logs to stdout.")
args = parser.parse_args()

# Optional file handle
log_file = open(args.logfile, "a") if args.logfile else None

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', MDNS_PORT))

# Join multicast group
mreq = struct.pack("4sl", socket.inet_aton(MDNS_GROUP), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print(f"Listening for Bonjour/mDNS packets on {MDNS_GROUP}:{MDNS_PORT}...\n")

try:
    while True:
        data, addr = sock.recvfrom(9000)
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%S%z')

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

        # Log to file or stdout
        output = json.dumps(log_entry)
        if log_file:
            log_file.write(output + "\n")
            log_file.flush()
        else:
            print(output)
except KeyboardInterrupt:
    print("Stopped listening.")
finally:
    if log_file:
        log_file.close()


