# main.py — text-only command interpreter with WiFi, BLE, UART bridge, terminal echo

import sys
import time
import select
import machine
import network
import ubinascii
import smble
import common
import passiveSniffers

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



# ---------------------------------------------------------------------------
# Global state: echo, input buffer, bridge mode
# ---------------------------------------------------------------------------

echo_enabled = True
buffer = []
bridge_mode = False
history = []
history_index = 0

history = []
history_index = 0

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

    # --- Arrow keys / escape sequences ---
    if ch == "\x1b":  # ESC
        # swallow next 2 bytes: '[' and the final code (A/B/C/D)
        if USE_USB:
            for _ in range(2):
                r, _, _ = select.select([sys.stdin], [], [], 0)
                if r:
                    sys.stdin.read(1)
        else:
            for _ in range(2):
                if uart.any():
                    uart.read(1)
        return None
    # -------------------------------------

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
    wlan.active(True)
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
# USB<->UART line-based forwarding
# ---------------------------------------------------------------------------

def bridge_loop():
    global bridge_mode
    common.write_line_usb("OK FORWARDING")
    while bridge_mode:
        # USB -> UART
        if USE_USB:
            line = common.read_line_usb()
            if line is not None:
                if isinstance(line, bytes):
                    line = line.decode(errors="ignore")
                line = line.rstrip("\r\n")
                if uart:
                    uart.write(line + "\n")
        # UART -> USB
        if uart:
            line = common.read_line_uart()
            if line is not None:
                if isinstance(line, bytes):
                    line = line.decode(errors="ignore")
                line = line.rstrip("\r\n")
                if USE_USB:
                    common.write_line_usb(line)
        time.sleep_ms(5)
    common.write_line_usb("OK STOPPED")

# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_ping(args):
    return "PONG"

def cmd_echo(args):
    return " ".join(args)

def cmd_info(args):
    import gc, time, network, os, sys, machine

    # --- Collect all data once ---
    uptime_s = time.ticks_ms() // 1000

    gc.collect()
    free_b = gc.mem_free()

    stat = os.statvfs('/')
    flash_total_b = stat[0] * stat[2]
    flash_free_b = stat[0] * stat[3]

    try:
        cpu_freq_hz = machine.freq()
    except:
        cpu_freq_hz = None

    try:
        uid_hex = machine.unique_id().hex()
    except:
        uid_hex = None

    platform = sys.platform
    mp_version = sys.version

    wlan = network.WLAN(network.STA_IF)
    wifi_active = wlan.active()
    wifi_connected = wlan.isconnected() if wifi_active else False

    ip = None
    mac = None

    if wifi_active:
        try:
            mac = wlan.config('mac').hex()
        except:
            mac = None

        if wifi_connected:
            ip = wlan.ifconfig()[0]

    # --- Section builders ---
    sections = {
        "uptime": "UPTIME=[{}s]".format(uptime_s),
        "cpu": "CPU=[{}Hz ID={}]".format(cpu_freq_hz, uid_hex),
        "memory": "MEM=[FREE={}B]".format(free_b),
        "flash": "FLASH=[TOTAL={}B FREE={}B]".format(flash_total_b, flash_free_b),
        "sw": "SW=[PLATFORM={} MPY={}]".format(platform, mp_version),
        "net": "NET=[BLE={} WIFI_ACTIVE={} WIFI_CONN={} IP={} MAC={}]".format(
            int(HAVE_BLE),
            int(wifi_active),
            int(wifi_connected),
            ip,
            mac
        )
    }

    # --- No args → full grouped output ---
    if not args:
        return " ".join([
            sections["uptime"],
            sections["cpu"],
            sections["memory"],
            sections["flash"],
            sections["sw"],
            sections["net"]
        ])

    # --- With args → return only requested section ---
    key = args[0].lower()

    if key in sections:
        return sections[key]

    return "ERR Unknown info section '{}'".format(key)


def cmd_help(args):
    cmds = sorted(COMMANDS.keys())
    return "CMDS:\n" + "\n".join(cmds)

#Wifi Handlers

def cmd_wifi_scan(args):
    aps = wifi_scan()
    #common.write_line_usb("OK WIFI_SCAN")
    for ap in aps:
        line = "SSID={ssid} BSSID={bssid} RSSI={rssi} CH={ch} AUTH={auth} HIDDEN={hidden}".format(**ap)
        common.write_line_usb(line)
    return "END"

def cmd_wifi_connect(args):
    if len(args) != 2:
        return "ERR ARGS: wifi_connect ssid password"
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
    res = smble.ble_scan()
    common.write_line_usb("OK BLE_SCAN")
    for dev in res:
        line = (
            "MAC={mac} TYPE={addr_type} RSSI={rssi} NAME={name} "
            "UUIDS={uuids} FLAGS={flags} TXP={txpower} ADV_HEX={adv_hex}"
        ).format(**dev)
        common.write_line_usb(line)
    return "END"

def cmd_ble_info(args):
    if not HAVE_BLE:
        return "ERR NO_BLE"
    info = smble.ble_info()
    return "ACTIVE={} MAC={}".format(info["active"], info["mac"])

def cmd_ble_reset(args):
    if not HAVE_BLE:
        return "ERR NO_BLE"
    ok = smble.ble_reset()
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

    # Informational header for the user
    common.write_line_usb("INFO SCANNING_HOSTS IP={} MASK={}".format(last_ip, last_mask))

    try:
        import netscan

        # Enable progress output
        hosts = netscan.scan_hosts(last_ip, last_mask, verbose=True)

        if not hosts:
            common.write_line_usb("INFO NO_HOSTS_FOUND")

        return "END"

    except Exception as e:
        return "ERR SCAN_HOSTS_" + str(e)

    
def cmd_scan_ports(args):
    # args = [ip] or [ip, profile] or [ip, custom, portlist]

    if len(args) < 1:
        return "ERR USAGE scan_ports <ip> [profile] [portlist]"

    target_ip = args[0]

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
            return "ERR USAGE scan_ports <ip> custom <p1,p2,p3>"
        try:
            ports = [int(p) for p in args[2].split(",")]
        except:
            return "ERR INVALID_PORTLIST"

    else:
        return "ERR UNKNOWN_PROFILE"

    # -------------------------
    # Perform scan
    # -------------------------
    try:
        import netscan
        open_ports = netscan.scan_ports(target_ip, ports, verbose=True)

        if not open_ports:
            return "OK SCAN_PORTS NONE"

        return "END"

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
            return "ERR USAGE scan_subnet custom <p1,p2,p3>"
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
        results = netscan.scan_subnet(last_ip, last_mask, ports, verbose=True)

        if not results:
            return "OK SCAN_SUBNET NONE"

        return "END"

    except Exception as e:
        return "ERR SCAN_SUBNET_" + str(e)


#Passive Sniffer Handlers

def cmd_sssd_listenner(args):
    passiveSniffers.sssd_listener()
    return "END"


#Pseudo OS Handlers

def cmd_exit(args):
    common.write_line_usb("OK EXIT")
    raise SystemExit

def cmd_reboot(args):
    common.write_line_usb("OK REBOOT")
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
        common.write_raw_usb("> ")


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

    "sniff_sssd": cmd_sssd_listenner,

    "echo_on": cmd_echo_on,
    "echo_off": cmd_echo_off,
    "echo_status": cmd_echo_status,

    "exit": cmd_exit,
    "reboot": cmd_reboot,
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


MOTD = [
    "",
    "   SniffyMole v2.0",
    "   SniffyMole — USB/UART Pentest Helper",
    "   Stay curious. Dig deeper.",
    ""
]

for line in MOTD:
    common.write_line_usb(line)

common.write_line_usb("READY")

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
            else:
                common.write_line_usb(result)
        except SystemExit:
            break
        except Exception as e:
            common.write_line_usb("ERR " + repr(e))
    else:
       common.write_line_usb("ERR UNKNOWN_CMD: " + cmd)

    # Always show prompt after processing a command
    show_prompt()
