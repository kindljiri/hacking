import socket
import struct

# Optional: Uncomment if you want to parse packets
# from dnslib import DNSRecord

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353

def ascii_dump(data):
    return ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data])

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
        print(f"Packet from {addr[0]}:{addr[1]}")
        print("Hex Dump:")
        print(data.hex())
        print("ASCII View:")
        print(ascii_dump(data))

        # Optional: Parse with dnslib
        # try:
        #     dns = DNSRecord.parse(data)
        #     print(" Parsed DNS Record:")
        #     print(dns)
        # except Exception as e:
        #     print(f"⚠️ Failed to parse DNS: {e}")

        print("-" * 60)
except KeyboardInterrupt:
    print("Stopped listening.")

