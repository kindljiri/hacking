# netscan.py — SniffyMole v2 network scanning module
# Pure functions, no command parsing, no globals.

import socket
import struct
import time


# ------------------------------------------------------------
# IP + Mask utilities
# ------------------------------------------------------------

def ip_to_int(ip):
    # Convert "A.B.C.D" → integer
    parts = ip.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

def int_to_ip(i):
    # Convert integer → "A.B.C.D"
    return "{}.{}.{}.{}".format(
        (i >> 24) & 0xFF,
        (i >> 16) & 0xFF,
        (i >> 8) & 0xFF,
        i & 0xFF
    )

def calc_network(ip, mask):
    """
    Given IP + MASK, return:
    - network address
    - broadcast address
    - CIDR prefix
    """
    ip_i = ip_to_int(ip)
    mask_i = ip_to_int(mask)

    network = ip_i & mask_i
    broadcast = network | (~mask_i & 0xFFFFFFFF)

    # Count bits in mask for CIDR
    cidr = bin(mask_i).count("1")

    return int_to_ip(network), int_to_ip(broadcast), cidr


def host_range(network_ip, broadcast_ip):
    """
    Yield all usable host IPs in the subnet.
    Excludes network and broadcast.
    """
    net = ip_to_int(network_ip)
    brd = ip_to_int(broadcast_ip)

    for i in range(net + 1, brd):
        yield int_to_ip(i)


# ------------------------------------------------------------
# Host probing
# ------------------------------------------------------------

def ping_host(ip, timeout_ms=200):
    timeout_s = timeout_ms / 1000

    test_ports = [22, 80, 443, 8080, 139, 445, 3389]

    for p in test_ports:
        try:
            s = socket.socket()
            s.settimeout(timeout_s)
            s.connect((ip, p))
            s.close()
            return True  # port open
        except OSError as e:
            errno = e.args[0]

            # Host is alive but port is closed or filtered
            if errno in (104, 111, 113, 110):
                return True

        except:
            pass

    return False


# ------------------------------------------------------------
# Port scanning
# ------------------------------------------------------------

def scan_ports(ip, ports, timeout_ms=250):
    """
    Scan a list of ports on a host.
    Returns list of open ports.
    """
    open_ports = []
    timeout_s = timeout_ms / 1000

    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(timeout_s)
            s.connect((ip, p))   # SUCCESS → port open
            s.close()
            open_ports.append(p)
        except OSError as e:
            # Closed ports raise OSError with errno 104/111/etc.
            # We IGNORE these because we only care about open ports.
            pass
        except:
            pass

    return open_ports

# ------------------------------------------------------------
# Network discovery
# ------------------------------------------------------------

def scan_hosts(ip, mask):
    """
    Return list of alive hosts in the subnet.
    """
    net, brd, _ = calc_network(ip, mask)
    alive = []

    for host in host_range(net, brd):
        if ping_host(host):
            alive.append(host)

    return alive


def scan_subnet(ip, mask, ports):
    """
    Full recon:
    - find alive hosts
    - scan ports on each
    Returns dict: {host: [open ports]}
    """
    results = {}
    hosts = scan_hosts(ip, mask)

    for h in hosts:
        results[h] = scan_ports(h, ports)

    return results
