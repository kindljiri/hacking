import machine
import sys
import select

def read_line_usb():
    r, _, _ = select.select([sys.stdin], [], [], 0)
    if r:
        return sys.stdin.readline()
    return None

def write_line_usb(msg):
    sys.stdout.write(msg + "\n")

def write_raw_usb(msg):
    sys.stdout.write(msg)

def read_line_uart():
    if uart and uart.any():
        return uart.readline()
    return None

def write_line_uart(msg):
    if uart:
        uart.write(msg + "\n")

def write_raw_uart(msg):
    if uart:
        uart.write(msg)
