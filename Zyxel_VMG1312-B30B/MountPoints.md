
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
/dev/sda1 on /mnt/usb1_1 type vfat (rw,relatime,fmask=0000,dmask=0000,allow_utime=0022,codepage=cp437,iocharset=iso8859-1,shortname=mixed)
usbfs on /proc/bus/usb type usbfs (rw,relatime)

~ # df -h
Filesystem                Size      Used Available Use% Mounted on
mtd:rootfs               17.1M     17.1M         0 100% /
/dev/mtdblock1            4.0M    452.0K      3.6M  11% /data
/dev/mtdblock3           41.1M      1.2M     39.9M   3% /firmware
/dev/sda1                28.6G      1.6M     28.6G   0% /mnt/usb1_1
```
