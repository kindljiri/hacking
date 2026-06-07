import ubinascii
import time

try:
    import bluetooth
    HAVE_BLE = True
except ImportError:
    HAVE_BLE = False


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
