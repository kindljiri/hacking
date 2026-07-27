# ADB Cheat Sheet
```
This cheat sheet is structured for embedded devices, kiosk ROMs, and root‑level exploration.
```
---

## Connection & Session Basics

### Check device connection
```
adb devices
```

### Open shell
```
adb shell
```

### Restart ADB server
```
adb kill-server adb start-server
```

### Wireless ADB
```
adb tcpip 5555 adb connect <IP>:5555
```

---

## File Operations

### Push file to device
```
adb push localfile /sdcard/
```

### Pull file from device
```
adb pull /sdcard/file .
```

### List files
```
adb shell ls -l /system
```

---

## App Management

### Install APK
```
adb install app.apk
```

### Reinstall/update APK
```
adb install -r app.apk
```

### Uninstall app
```
adb uninstall com.example.app
```

---

## System Information

### System properties
```
adb shell getprop
```

### CPU info
```
adb shell cat /proc/cpuinfo
```

### Memory info
```
adb shell cat /proc/meminfo
```

### Partition table
```
adb shell ls -l /dev/block/by-name
```

### Boot parameters
```
adb shell cat /proc/cmdline
```

---

## System Services & Debugging

### Window manager state
```
adb shell dumpsys window
```

### Accessibility services
```
adb shell dumpsys accessibility
```

### Package manager info
```
adb shell dumpsys package
```

### Service list
```
adb shell service list
```

---

## Networking

### IP info
```
adb shell ip addr show
```

### Wi‑Fi logs
```
adb shell dmesg | grep -i wifi
```

---

## USB / HID / OTG

### USB devices
```
adb shell lsusb
```

### OTG state
```
adb shell cat /sys/kernel/debug/usb/otg_state
```

### Input devices
```
adb shell getevent -p
```

---

## Root‑Level Commands

### Remount /system RW
```
adb shell su -c "mount -o remount,rw /system"
```

### Dump partitions
```
adb shell su -c "dd if=/dev/block/by-name/system of=/sdcard/system.img"
```

### Edit keylayout
```
adb shell su -c "nano /system/usr/keylayout/Generic.kl"
```

### Inspect init scripts
```
adb shell su -c "cat /init.rc"
```

---

## Kiosk‑Bypass Commands

### Open settings
```
adb shell am start -a android.settings.SETTINGS
```

### Open accessibility settings
```
adb shell am start -a android.settings.ACCESSIBILITY_SETTINGS
```

### Simulate HOME key
```
adb shell input keyevent 3
```

### Simulate BACK key
```
adb shell input keyevent 4
```