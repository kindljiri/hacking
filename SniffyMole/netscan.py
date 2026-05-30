# netscan.py — SniffyMole v2 network scanning module
# Pure functions, no command parsing, no globals.

import socket
import struct
import time


# ------------------------------------------------------------
# IP + Mask utilities
# ------------------------------------------------------------

def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(i):
    return socket.inet_ntoa(struct.pack("!I", i))


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

def ping_host(ip, timeout_ms=100):
    """
    Multi-port host liveness detection.
    Returns True if ANY tested port responds with:
    - 0   (open)
    - 111 (connection refused, host alive)
    """
    test_ports = [22, 80, 443, 8080, 139, 445, 3389]

    for p in test_ports:
        try:
            s = socket.socket()
            s.settimeout(timeout_ms / 1000)
            r = s.connect_ex((ip, p))
            s.close()

            if r == 0 or r == 111:
                return True

        except:
            pass

    return False

# ------------------------------------------------------------
# Port scanning
# ------------------------------------------------------------

def scan_ports(ip, ports, timeout_ms=100):
    """
    Scan a list of ports on a host.
    Returns list of open ports.
    """
    open_ports = []

    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(timeout_ms / 1000)
            r = s.connect_ex((ip, p))
            s.close()
            if r == 0:
                open_ports.append(p)
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
    hosts = discover_hosts(ip, mask)

    for h in hosts:
        results[h] = scan_ports(h, ports)

    return results
