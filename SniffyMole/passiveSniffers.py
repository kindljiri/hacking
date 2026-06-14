# passiveSniffers.py

import usocket as socket
import json
import utime
from common import write_line_usb

SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900
INTERFACE_IP = "0.0.0.0"

def _parse_ssdp(raw):
    headers = {}
    lines = raw.split("\r\n")
    if lines:
        headers["method"] = lines[0]
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().upper()] = v.strip()
    return headers


def sssd_listener():
    """
    Passive SSDP listener for SniffyMole.
    Broadcast-only (no multicast join).
    Outputs structured JSON via USB.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((INTERFACE_IP, SSDP_PORT))
    except Exception as e:
        write_line_usb(json.dumps({"error": "bind_failed", "detail": str(e)}))
        return

    write_line_usb(json.dumps({
        "event": "ssdp_listener_started",
        "note": "broadcast-only (multicast unsupported)"
    }))

    while True:
        sock.settimeout(1)
        try:
            data, addr = sock.recvfrom(1024)
        except OSError:
            continue  # timeout

        try:
            msg = data.decode("utf-8", "ignore")
        except:
            msg = ""

        parsed = _parse_ssdp(msg)

        event = {
            "ts": utime.time(),
            "from": addr[0],
            "port": addr[1],
            "ssdp": parsed
        }

        write_line_usb(json.dumps(event))
