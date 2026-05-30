#Zyxel Firmware hacking

## Extract firmware

Get info about firmware downloaded from device via SPI or from vendor

```
binwalk VMG1312-B30B__100AAEE0b25.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
131072        0x20000         JFFS2 filesystem, big endian
```

### JFFS2 Extraction

We see the where the jffs2 in section above start at adress 131072 so we will skip to that address and get data with dd.
We verify with file command. 

```
dd if=VMG1312-B30B__100AAEE0b25.bin of=rootfs.jffs2 bs=1 skip=131072
18638729+0 records in
18638729+0 records out
18638729 bytes (19 MB, 18 MiB) copied, 35.6136 s, 523 kB/s

file rootfs.jffs2
rootfs.jffs2: Linux jffs2 filesystem data big endian
```
mkdir jffs2-extracted
mount -t jffs2 rootfs.jffs2 jffs2-extracted