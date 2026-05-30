[Main Page](README.md)

# Hardware information

## CPU

```
> cat /proc/cpuinfo
system type             : 963168VXB
processor               : 0
cpu model               : Broadcom4350 V8.0
BogoMIPS                : 398.33
wait instruction        : yes
microsecond timers      : yes
tlb_entries             : 32
extra interrupt vector  : no
hardware watchpoint     : no
ASEs implemented        :
shadow register sets    : 1
core                    : 0
VCED exceptions         : not available
VCEI exceptions         : not available
unaligned exceptions            : 1996

processor               : 1
cpu model               : Broadcom4350 V8.0
BogoMIPS                : 402.43
wait instruction        : yes
microsecond timers      : yes
tlb_entries             : 32
extra interrupt vector  : no
hardware watchpoint     : no
ASEs implemented        :
shadow register sets    : 1
core                    : 0
VCED exceptions         : not available
VCEI exceptions         : not available
unaligned exceptions            : 1996

```

## RAM
```
 > meminfo
Total MDM Shared Memory Region : 2432KB
Shared Memory Usable           : 002320KB
Shared Memory in-use           : 000163KB
Shared Memory free             : 002156KB
Shared Memory allocs           : 038811
Shared Memory frees            : 036237
Shared Memory alloc/free delta : 002574

Heap bytes in-use     : 000016
Heap allocs           : 000076
Heap frees            : 000075
Heap alloc/free delta : 000001


 > sysstate mem
MemTotal: 58800 kB (60211200 bytes)
MemTotalFree: 3200 kB (3276800 bytes)
```

## Flash

## Storage

```
 > df -h
Filesystem                Size      Used Available Use% Mounted on
mtd:rootfs               17.1M     17.1M         0 100% /
/dev/mtdblock1            4.0M    456.0K      3.6M  11% /data
/dev/mtdblock3           41.1M      1.2M     40.0M   3% /firmware
```
```
~ # mount
rootfs on / type rootfs (rw)
mtd:rootfs on / type jffs2 (ro,relatime)
proc on /proc type proc (rw,relatime)
tmpfs on /var type tmpfs (rw,relatime,size=420k)
tmpfs on /mnt type tmpfs (rw,relatime,size=16k)
sysfs on /sys type sysfs (rw,relatime)
/dev/mtdblock1 on /data type jffs2 (rw,relatime)
/dev/mtdblock3 on /firmware type jffs2 (rw,relatime)
/dev/sda1 on /mnt/usb1_1 type vfat (rw,relatime,fmask=0000,dmask=0000,allow_utime0022,codepage=cp437,iocharset=iso8859-1,shortname=mixed)
usbfs on /proc/bus/usb type usbfs (rw,relatime)
```

[Main Page](README.md)