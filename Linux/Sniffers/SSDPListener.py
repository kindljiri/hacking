import socket
import json
from datetime import datetime
import threading
import time

SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900
LOG_FILE = "ssdp_log.jsonl"
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
        print(f"M-SEARCH sent to {SSDP_GROUP}:{SSDP_PORT}")
        time.sleep(SEARCH_INTERVAL)

def listen_ssdp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((INTERFACE_IP, SSDP_PORT))
    mreq = socket.inet_aton(SSDP_GROUP) + socket.inet_aton(INTERFACE_IP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

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

            print(json.dumps(event, indent=2))
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(event) + "\n")
    except KeyboardInterrupt:
        print("\n Listener stopped.")

# Run sender and listener in parallel
threading.Thread(target=send_msearch, daemon=True).start()
listen_ssdp()