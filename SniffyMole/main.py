# main.py — text-only command interpreter with WiFi, BLE, UART bridge, terminal echo

import sys
import time
import select
import machine
import network
import ubinascii

try:
    import bluetooth
    HAVE_BLE = True
except ImportError:
    HAVE_BLE = False

# ---------------------------------------------------------------------------
# Interface selection (USB CDC preferred, fallback to UART)
# ---------------------------------------------------------------------------

USE_USB = hasattr(sys.stdin, "read")

# UART config
UART_ID = 0
UART_BAUD_DEFAULT = 115200
uart = None
uart_baud = UART_BAUD_DEFAULT

def init_uart(baud=None):
    global uart, uart_baud
    if baud is None:
        baud = UART_BAUD_DEFAULT
    uart_baud = baud
    uart = machine.UART(UART_ID, baudrate=uart_baud)

if not USE_USB:
    init_uart()

def read_line_usb():
    r, _, _ = select.select([sys.stdin], [], [], 0)
    if r:
        return sys.stdin.readline()
    return None

def write_line_usb(msg):
    sys.stdout.write(msg + "\n")

def read_line_uart():
    if uart and uart.any():
        return uart.readline()
    return None

def write_line_uart(msg):
    if uart:
        uart.write(msg + "\n")

def write_line(msg):
    if USE_USB:
        write_line_usb(msg)
    else:
        write_line_uart(msg)

def write_raw(msg):
    if USE_USB:
        sys.stdout.write(msg)
    else:
        uart.write(msg)

# ---------------------------------------------------------------------------
# Global state: echo, input buffer, bridge mode
# ---------------------------------------------------------------------------

echo_enabled = True
buffer = []
bridge_mode = False

def read_line():
    global echo_enabled, buffer

    # Read one character
    if USE_USB:
        r, _, _ = select.select([sys.stdin], [], [], 0)
        if not r:
            return None
        ch = sys.stdin.read(1)
    else:
        if not uart.any():
            return None
        ch = uart.read(1)
        if ch:
            ch = ch.decode(errors="ignore")

    if not ch:
        return None

    # --- Backspace handling ---
    if ch in ("\x08", "\x7f"):  # backspace or delete
        if buffer:
            buffer.pop()
            if echo_enabled and not bridge_mode:
                if USE_USB:
                    sys.stdout.write("\b \b")
                else:
                    uart.write("\b \b")
        return None

    # --- Echo ---
    if echo_enabled and not bridge_mode:
        if USE_USB:
            sys.stdout.write(ch)
        else:
            uart.write(ch)

    # --- Line termination ---
    if ch in ("\r", "\n"):
        line = "".join(buffer)
        buffer.clear()
        return line

    # --- Normal character ---
    buffer.append(ch)
    return None

# ---------------------------------------------------------------------------
# WiFi helpers
# ---------------------------------------------------------------------------

wlan = network.WLAN(network.STA_IF)
wlan.active(True)

def wifi_scan():
    aps = []
    for entry in wlan.scan():
        ssid, bssid, channel, rssi, authmode, hidden = entry
        aps.append({
            "ssid": ssid.decode() if isinstance(ssid, bytes) else ssid,
            "bssid": ubinascii.hexlify(bssid, ":").decode(),
            "ch": channel,
            "rssi": rssi,
            "auth": authmode,
            "hidden": hidden,
        })
    return aps

def wifi_connect(ssid, password, timeout=10):
    wlan.active(True)
    if not wlan.isconnected():
        wlan.connect(ssid, password)
        for _ in range(timeout * 10):
            if wlan.isconnected():
                break
            time.sleep_ms(100)
    return wlan.isconnected()

def wifi_status():
    info = {}
    info["active"] = int(wlan.active())
    info["connected"] = int(wlan.isconnected())
    try:
        info["ifconfig"] = wlan.ifconfig()
    except:
        info["ifconfig"] = None
    try:
        info["ssid"] = wlan.config("essid")
    except:
        info["ssid"] = ""
    try:
        info["mac"] = ubinascii.hexlify(wlan.config("mac"), ":").decode()
    except:
        info["mac"] = ""
    return info

def wifi_disconnect():
    try:
        wlan.disconnect()
    except:
        pass
    wlan.active(False)

def refresh_wifi_info():
    """
    Refresh Wi-Fi info by calling wifi_status().
    Updates last_ip, last_mask, last_gw.
    Returns True if Wi-Fi is active and connected.
    """
    global last_ip, last_mask, last_gw

    info = wifi_status()

    # Must be active AND connected
    if not info.get("active") or not info.get("connected"):
        last_ip = None
        last_mask = None
        last_gw = None
        return False

    ifconfig = info.get("ifconfig")
    if not ifconfig:
        last_ip = None
        last_mask = None
        last_gw = None
        return False

    # ifconfig = (ip, mask, gw, dns)
    ip, mask, gw, _ = ifconfig

    last_ip = ip
    last_mask = mask
    last_gw = gw

    return True


# ---------------------------------------------------------------------------
# BLE helpers (HEX + partial decode)
# ---------------------------------------------------------------------------

ble = None
ble_scan_results = []

def ble_init():
    global ble
    if not HAVE_BLE:
        return
    if ble is None:
        ble = bluetooth.BLE()
        ble.active(True)

def _decode_name(adv):
    i = 0
    while i + 1 < len(adv):
        length = adv[i]
        if length == 0:
            break
        if i + 1 + length > len(adv):
            break
        ad_type = adv[i + 1]
        if ad_type in (0x08, 0x09):
            return adv[i + 2:i + 1 + length].decode(errors="ignore")
        i += 1 + length
    return ""

def _decode_uuids(adv):
    uuids = []
    i = 0
    while i + 1 < len(adv):
        length = adv[i]
        if length == 0:
            break
        if i + 1 + length > len(adv):
            break
        ad_type = adv[i + 1]
        data = adv[i + 2:i + 1 + length]
        if ad_type in (0x02, 0x03):  # 16-bit UUIDs
            for j in range(0, len(data), 2):
                if j + 2 <= len(data):
                    u = data[j:j+2]
                    uuids.append("0x%04X" % int.from_bytes(u, "little"))
        elif ad_type in (0x06, 0x07):  # 128-bit UUIDs
            for j in range(0, len(data), 16):
                if j + 16 <= len(data):
                    u = data[j:j+16]
                    uuids.append(ubinascii.hexlify(u).decode())
        i += 1 + length
    return uuids

def _decode_flags(adv):
    i = 0
    while i + 1 < len(adv):
        length = adv[i]
        if length == 0:
            break
        if i + 1 + length > len(adv):
            break
        ad_type = adv[i + 1]
        if ad_type == 0x01 and length >= 2:
            return "0x%02X" % adv[i + 2]
        i += 1 + length
    return ""

def _decode_txpower(adv):
    i = 0
    while i + 1 < len(adv):
        length = adv[i]
        if length == 0:
            break
        if i + 1 + length > len(adv):
            break
        ad_type = adv[i + 1]
        if ad_type == 0x0A and length >= 2:
            val = adv[i + 2]
            if val & 0x80:
                val = val - 256
            return str(val)
        i += 1 + length
    return ""

def ble_irq(event, data):
    global ble_scan_results
    if event == bluetooth._IRQ_SCAN_RESULT:
        addr_type, addr, adv_type, rssi, adv_data = data
        mac = ubinascii.hexlify(addr, ":").decode()
        adv = bytes(adv_data)
        name = _decode_name(adv)
        uuids = _decode_uuids(adv)
        flags = _decode_flags(adv)
        txp = _decode_txpower(adv)
        ble_scan_results.append({
            "mac": mac,
            "addr_type": addr_type,
            "rssi": rssi,
            "adv_hex": ubinascii.hexlify(adv).decode(),
            "name": name,
            "uuids": ",".join(uuids),
            "flags": flags,
            "txpower": txp,
        })
    elif event == bluetooth._IRQ_SCAN_DONE:
        pass

def ble_scan(duration_ms=5000):
    global ble_scan_results
    if not HAVE_BLE:
        return None
    ble_init()
    ble_scan_results = []
    ble.irq(ble_irq)
    ble.gap_scan(duration_ms, 30000, 30000)
    t0 = time.ticks_ms()
    while time.ticks_diff(time.ticks_ms(), t0) < duration_ms + 500:
        time.sleep_ms(100)
    ble.gap_scan(None)
    return ble_scan_results

def ble_info():
    if not HAVE_BLE:
        return None
    ble_init()
    info = {}
    try:
        mac = ble.config("mac")
        info["mac"] = ubinascii.hexlify(mac, ":").decode()
    except:
        info["mac"] = ""
    info["active"] = int(ble.active())
    return info

def ble_reset():
    if not HAVE_BLE:
        return False
    ble.active(False)
    time.sleep_ms(100)
    ble.active(True)
    return True

# ---------------------------------------------------------------------------
# USB<->UART line-based forwarding
# ---------------------------------------------------------------------------

def bridge_loop():
    global bridge_mode
    write_line("OK FORWARDING")
    while bridge_mode:
        # USB -> UART
        if USE_USB:
            line = read_line_usb()
            if line is not None:
                if isinstance(line, bytes):
                    line = line.decode(errors="ignore")
                line = line.rstrip("\r\n")
                if uart:
                    uart.write(line + "\n")
        # UART -> USB
        if uart:
            line = read_line_uart()
            if line is not None:
                if isinstance(line, bytes):
                    line = line.decode(errors="ignore")
                line = line.rstrip("\r\n")
                if USE_USB:
                    write_line_usb(line)
        time.sleep_ms(5)
    write_line("OK STOPPED")

# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_ping(args):
    return "PONG"

def cmd_echo(args):
    return " ".join(args)

def cmd_info(args):
    import gc
    uptime = time.ticks_ms() // 1000
    gc.collect()
    free = gc.mem_free()
    return "UPTIME={}s FREE={} FW=main.py".format(uptime, free)

def cmd_help(args):
    cmds = sorted(COMMANDS.keys())
    return "CMDS:\n" + "\n".join(cmds)

#Wifi Handlers

def cmd_wifi_scan(args):
    aps = wifi_scan()
    write_line("OK WIFI_SCAN")
    for ap in aps:
        line = "SSID={ssid} BSSID={bssid} RSSI={rssi} CH={ch} AUTH={auth} HIDDEN={hidden}".format(**ap)
        write_line(line)
    return "END"

def cmd_wifi_connect(args):
    if len(args) != 2:
        return "ERR ARGS"
    ssid = args[0]
    password = args[1]
    ok = wifi_connect(ssid, password)
    if ok:
        st = wifi_status()
        ip, mask, gw, dns = st["ifconfig"]
        return "CONNECTED IP={} MASK={} GW={}".format(ip, mask, gw)
    else:
        return "CONNECT_FAILED"

def cmd_wifi_status(args):
    st = wifi_status()
    if not st["ifconfig"]:
        return "ACTIVE={} CONNECTED={}".format(st["active"], st["connected"])
    ip, mask, gw, dns = st["ifconfig"]
    return "ACTIVE={} CONNECTED={} SSID={} IP={} MASK={} GW={} MAC={}".format(
        st["active"], st["connected"], st["ssid"], ip, mask, gw, st["mac"]
    )

def cmd_wifi_disconnect(args):
    wifi_disconnect()
    return "DISCONNECTED"

#BLE Handlers

def cmd_ble_scan(args):
    if not HAVE_BLE:
        return "ERR NO_BLE"
    res = ble_scan()
    write_line("OK BLE_SCAN")
    for dev in res:
        line = (
            "MAC={mac} TYPE={addr_type} RSSI={rssi} NAME={name} "
            "UUIDS={uuids} FLAGS={flags} TXP={txpower} ADV_HEX={adv_hex}"
        ).format(**dev)
        write_line(line)
    return "END"

def cmd_ble_info(args):
    if not HAVE_BLE:
        return "ERR NO_BLE"
    info = ble_info()
    return "ACTIVE={} MAC={}".format(info["active"], info["mac"])

def cmd_ble_reset(args):
    if not HAVE_BLE:
        return "ERR NO_BLE"
    ok = ble_reset()
    return "BLE_RESET" if ok else "ERR BLE_RESET"

#UART Handlers

def cmd_uart_set(args):
    if len(args) != 1:
        return "ERR ARGS"
    try:
        baud = int(args[0])
    except:
        return "ERR BAD_BAUD"
    if baud < 1200 or baud > 921600:
        return "ERR BAD_BAUD"
    init_uart(baud)
    return "BAUD={}".format(baud)

def cmd_uart_get(args):
    return "BAUD={}".format(uart_baud)

def cmd_usb2uart_start(args):
    global bridge_mode
    if uart is None:
        return "ERR NO_UART"
    bridge_mode = True
    bridge_loop()
    return ""

def cmd_usb2uart_stop(args):
    global bridge_mode
    bridge_mode = False
    return ""

#TCP SCAN Handlers

def cmd_scan_hosts(args):
    if not refresh_wifi_info():
        return "ERR NO_WIFI"

    # Status line
    write_line("INFO SCANNING_HOSTS IP={} MASK={}".format(last_ip, last_mask))

    try:
        import netscan
        hosts = netscan.scan_hosts(last_ip, last_mask)

        if not hosts:
            return "OK SCAN_HOSTS NONE"

        return "OK SCAN_HOSTS " + " ".join(hosts)

    except Exception as e:
        return "ERR SCAN_HOSTS_" + str(e)
    
def cmd_scan_ports(args):
    # Minimum: scan ports <ip>
    if len(args) < 2:
        return "ERR USAGE scan ports <ip> [profile] [portlist]"

    target_ip = args[1]

    # Default profile = common
    mode = "common"
    if len(args) >= 3:
        mode = args[2]

    # -------------------------
    # Port profiles
    # -------------------------
    if mode == "common":
        ports = [22, 80, 443, 8080, 139, 445, 3389]

    elif mode == "extended":
        ports = list(range(1, 1025))

    elif mode == "full":
        ports = list(range(1, 65536))

    elif mode == "custom":
        if len(args) != 4:
            return "ERR USAGE scan ports <ip> custom <p1,p2,p3>"
        try:
            ports = [int(p) for p in args[3].split(",")]
        except:
            return "ERR INVALID_PORTLIST"

    else:
        return "ERR UNKNOWN_PROFILE"

    # -------------------------
    # Perform scan
    # -------------------------
    try:
        import netscan
        open_ports = netscan.scan_ports(target_ip, ports)

        if not open_ports:
            return "OK SCAN_PORTS NONE"

        return "OK SCAN_PORTS " + ",".join(str(p) for p in open_ports)

    except Exception as e:
        return "ERR SCAN_PORTS_" + str(e)
    
def cmd_scan_subnet(args):
    if not refresh_wifi_info():
        return "ERR NO_WIFI"

    # Default profile = common
    mode = "common"
    if len(args) >= 2:
        mode = args[1]

    # -------------------------
    # Port profiles
    # -------------------------
    if mode == "common":
        ports = [22, 80, 443, 8080, 139, 445, 3389]

    elif mode == "extended":
        ports = list(range(1, 1025))

    elif mode == "full":
        ports = list(range(1, 65536))

    elif mode == "custom":
        if len(args) != 3:
            return "ERR USAGE scan subnet custom <p1,p2,p3>"
        try:
            ports = [int(p) for p in args[2].split(",")]
        except:
            return "ERR INVALID_PORTLIST"

    else:
        return "ERR UNKNOWN_PROFILE"

    # -------------------------
    # Perform subnet scan
    # -------------------------
    try:
        import netscan
        results = netscan.scan_subnet(last_ip, last_mask, ports)

        if not results:
            return "OK SCAN_SUBNET NONE"

        # Format:
        # HOST <ip> <comma-separated-open-ports>
        lines = []
        for host, open_ports in results.items():
            if open_ports:
                ports_str = ",".join(str(p) for p in open_ports)
            else:
                ports_str = "NONE"
            lines.append(f"HOST {host} {ports_str}")

        return "OK SCAN_SUBNET\n" + "\n".join(lines)

    except Exception as e:
        return "ERR SCAN_SUBNET_" + str(e)


#Pseudo OS Handlers

def cmd_exit(args):
    write_line("OK EXIT")
    raise SystemExit

def cmd_reboot(args):
    write_line("OK REBOOT")
    time.sleep_ms(100)
    machine.reset()

def cmd_echo_on(args):
    global echo_enabled
    echo_enabled = True
    return "ECHO=ON"

def cmd_echo_off(args):
    global echo_enabled
    echo_enabled = False
    return "ECHO=OFF"

def cmd_echo_status(args):
    return "ECHO={}".format("ON" if echo_enabled else "OFF")

def show_prompt():
    if not bridge_mode and echo_enabled:
        write_raw("> ")


# ---------------------------------------------------------------------------
# Command table (case-sensitive)
# ---------------------------------------------------------------------------

COMMANDS = {
    "ping": cmd_ping,
    "echo": cmd_echo,
    "info": cmd_info,
    "help": cmd_help,

    "wifi_scan": cmd_wifi_scan,
    "wifi_connect": cmd_wifi_connect,
    "wifi_status": cmd_wifi_status,
    "wifi_disconnect": cmd_wifi_disconnect,

    "ble_scan": cmd_ble_scan,
    "ble_info": cmd_ble_info,
    "ble_reset": cmd_ble_reset,

    "uart_set": cmd_uart_set,
    "uart_get": cmd_uart_get,
    "usb2uart_start": cmd_usb2uart_start,
    "usb2uart_stop": cmd_usb2uart_stop,

    "scan_hosts": cmd_scan_hosts,
    "scan_ports": cmd_scan_ports,
    "scan_subnet": cmd_scan_subnet,

    "echo_on": cmd_echo_on,
    "echo_off": cmd_echo_off,
    "echo_status": cmd_echo_status,

    "exit": cmd_exit,
    "reboot": cmd_reboot,
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

write_line("SniffyMole v2.0")

MOTD = [
    "",
    "   SniffyMole — USB/UART Pentest Helper",
    "   Stay curious. Dig deeper.",
]

for line in MOTD:
    write_line(line)

write_line("READY")

# Show prompt at startup
show_prompt()

while True:
    line = read_line()
    if line is None:
        time.sleep_ms(5)
        continue

    if line == "":
        show_prompt()
        continue

    parts = line.split()
    cmd = parts[0]
    args = parts[1:]

    handler = COMMANDS.get(cmd)
    if handler:
        try:
            result = handler(args)
            if result is None:
                show_prompt()
                continue
            if result == "":
                show_prompt()
                continue
            if result.startswith("ERR "):
                write_line(result)
            else:
                write_line("OK " + result)
        except SystemExit:
            break
        except Exception as e:
            write_line("ERR " + repr(e))
    else:
        write_line("ERR UNKNOWN_CMD: " + cmd)

    # Always show prompt after processing a command
    show_prompt()
