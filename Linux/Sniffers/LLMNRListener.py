#!/usr/bin/env python3

import socket
import struct
import json
import time
import argparse
import sys

LLMNR_GROUP = "224.0.0.252"
LLMNR_PORT = 5355
BUFFER_SIZE = 4096

def ascii_dump(data):
    return ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data])

# Parse command-line arguments
parser = argparse.ArgumentParser(
    description="Passive LLMNR listener with structured JSON logging."
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
sock.bind(('', LLMNR_PORT))

# Join multicast group
mreq = struct.pack("4sl", socket.inet_aton(LLMNR_GROUP), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

if not args.quiet:
    print(f"Listening for LLMNR packets on {LLMNR_GROUP}:{LLMNR_PORT}...\n")

try:
    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%S%z')
        packet_count += 1

        log_entry = {
            "timestamp": timestamp,
            "source_ip": addr[0],
            "source_port": addr[1],
            "length": len(data),
            "hex": data.hex(),
            "ascii": ascii_dump(data)
        }

        output = json.dumps(log_entry)

        if log_file:
            log_file.write(output + "\n")
            log_file.flush()

        if not args.quiet and not log_file:
            print(json.dumps(log_entry, indent=2))
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
