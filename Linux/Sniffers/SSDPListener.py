#!/usr/bin/env python3

import socket
import json
import argparse
import sys
import threading
import time
from datetime import datetime

SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900
INTERFACE_IP = "0.0.0.0"
MX = 2  # Wait time for responses in seconds
SEARCH_INTERVAL = 60  # Seconds between M-SEARCH bursts

def parse_ssdp(raw_message):
    headers = {}
    lines = raw_message.splitlines()
    if lines:
        headers["method"] = lines[0]
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().upper()] = value.strip()
    return headers

def send_msearch():
    message = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        f"HOST: {SSDP_GROUP}:{SSDP_PORT}",
        "MAN: \"ssdp:discover\"",
        f"MX: {MX}",
        "ST: ssdp:all",
        "", ""
    ]).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    while True:
        sock.sendto(message, (SSDP_GROUP, SSDP_PORT))
        time.sleep(SEARCH_INTERVAL)

def listen_ssdp(log_file=None, quiet=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((INTERFACE_IP, SSDP_PORT))
    mreq = socket.inet_aton(SSDP_GROUP) + socket.inet_aton(INTERFACE_IP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    packet_count = 0

    if not quiet:
        print(f"Listening for SSDP packets on {SSDP_GROUP}:{SSDP_PORT}...\n")

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            msg = data.decode("utf-8", errors="ignore")
            parsed = parse_ssdp(msg)

            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "from": addr[0],
                "port": addr[1],
                "ssdp": parsed
            }

            output = json.dumps(event)

            if log_file:
                log_file.write(output + "\n")
                log_file.flush()

            packet_count += 1

            if not quiet and not log_file:
                print(json.dumps(event, indent=2))
            elif log_file and not quiet:
                print(f"Captured {packet_count} packet{'s' if packet_count > 1 else ''}...", end='\r')
    except KeyboardInterrupt:
        if log_file and not quiet:
            print(f"\nStopped listening. Total packets captured: {packet_count}")
        elif not quiet:
            print("\nStopped listening.")
        if log_file:
            log_file.close()

# Parse command-line arguments
parser = argparse.ArgumentParser(
    description="Listen for SSDP packets and log them in structured JSON format."
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
log_file_handle = open(args.logfile, "a") if args.logfile else None

# Run sender and listener in parallel
threading.Thread(target=send_msearch, daemon=True).start()
listen_ssdp(log_file=log_file_handle, quiet=args.quiet)
