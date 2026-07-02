#!/bin/bash


echo "=== DEVICE INFO REPORT ==="
echo "Generated: $(date)"
echo "" 

section() {
  echo ""
  echo "===================================="
  echo "== $1"
  echo "===================================="
  echo ""
}

cmd() {
  echo "\$ $1" 
  adb shell $1 2>&1
  echo "" 
}

section "BUILD & PRODUCT INFO"
cmd "getprop ro.build.fingerprint"
cmd "getprop ro.build.display.id"
cmd "getprop ro.product.model"
cmd "getprop ro.product.name"
cmd "getprop ro.product.device"
cmd "getprop ro.hardware"
cmd "getprop ro.bootloader"

section "CPU & MEMORY"
cmd "cat /proc/cpuinfo"
cmd "cat /proc/meminfo"
cmd "free -m"

section "ZRAM"
cmd "ls /sys/block | grep zram"
cmd "cat /sys/block/zram0/disksize"
cmd "cat /sys/block/zram0/comp_algorithm"

section "STORAGE & PARTITIONS"
cmd "cat /proc/partitions"
cmd "ls -l /dev/block/by-name"
cmd "mount"
cmd "df -h"

section "FSTAB"
cmd "cat /fstab.*"
cmd "cat /system/etc/fstab.*"

section "KERNEL & DRIVERS"
cmd "uname -a"
cmd "cat /proc/version"
cmd "lsmod"
cmd "dmesg | grep -i rockchip"
cmd "dmesg | grep -i mmc"
cmd "dmesg | grep -i nand"

section "LCD & TOUCH"
cmd "getprop ro.boot.lcd"
cmd "getprop ro.boot.tp"
cmd "dmesg | grep -i lcd"
cmd "dmesg | grep -i panel"
cmd "dmesg | grep -i touch"
cmd "cat /proc/bus/input/devices"

section "INPUT DEVICES & KEYLAYOUTS"
cmd "getevent -p"
cmd "ls /system/usr/keylayout"
cmd "cat /system/usr/keylayout/Generic.kl"

section "USB / OTG / HID"
cmd "lsusb"
cmd "dmesg | grep -i usb"
cmd "cat /sys/kernel/debug/usb/otg_state"
cmd "getprop sys.usb.config"

section "NETWORK & WIFI"
cmd "ip link"
cmd "ifconfig -a"
cmd "dmesg | grep -i wifi"
cmd "lsmod | grep -i 8188"

section "SYSTEM SERVICES"
cmd "service list"
cmd "dumpsys activity"
cmd "dumpsys package"
cmd "dumpsys window"
cmd "dumpsys window policy"

section "ACCESSIBILITY"
cmd "dumpsys accessibility"

section "BOOT PARAMETERS"
cmd "cat /proc/cmdline"

section "RECOVERY & BOOT PARTITIONS"
cmd "ls -l /dev/block/by-name/recovery"
cmd "ls -l /dev/block/by-name/boot"

section "SELINUX"
cmd "getenforce"
cmd "cat /sys/fs/selinux/enforce"

section "LOGCAT SNAPSHOTS"
cmd "logcat -d | grep -i systemui"
cmd "logcat -d | grep -i overlay"
cmd "logcat -d | grep -i permission"

echo "=== REPORT COMPLETE ===" 