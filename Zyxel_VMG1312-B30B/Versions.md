[Main Page](README.md)

# Versions

Versions can give us idea what we are dealing with and it is potential attacke surfice to exploit.
You can get most from Boot output, but when you not having UART access it is good to know some commands.

## Boot loader
We know this from [Boot Output](BootOutput.md)
```
CFE version 1.0.38-112.37 for BCM963268 (32bit,SP,BE)
Build Date: 03/18/2015 (release@iBuild)
Copyright (C) 2000-2011 Broadcom Corporation.
```

## Linux kernel
We can get it from Boot output or by running command:
```
> echo $(uname -a)
Linux (none) 2.6.30 #3 SMP PREEMPT Wed Mar 18 15:05:13 CST 2015 mips GNU/Linux
```

## Firmware
I guess it is firmware:
```
 > swversion show
1.00(AAEE.0)b23
```

## BusyBox
I got this bit by mistake put it might be the way
```
 > ps axu
ps: invalid option -- a
BusyBox v1.17.2 (2015-03-17 17:51:42 CST) multi-call binary.
```

[Main Page](README.md)