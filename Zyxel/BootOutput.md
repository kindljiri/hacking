[Main Page](README.md)

# Boot output

```
HELO
CPUI
L1CI
HELO
CPUI
L1CI
DRAM
----
PHYS
STRF
400H
PHYE
DDR2
DINT
USYN
LSYN
MFAS
LMBE
RACE
PASS
----
ZBSS
CODE
DATA
L12F
MAIN
COMS
COME
SUCC

CFE version 1.0.38-112.37 for BCM963268 (32bit,SP,BE)
Build Date: 03/18/2015 (release@iBuild)
Copyright (C) 2000-2011 Broadcom Corporation.

NAND flash device: name <not identified>, id 0x0000 block 128KB size 131072KB
Chip ID: BCM63168D0, MIPS: 400MHz, DDR: 400MHz, Bus: 200MHz
Main Thread: TP0
Memory Test Passed
Total Memory: 67108864 bytes (64MB)
Boot Address: 0xb8000000

Board IP address                  : 192.168.1.1:ffffff00  
Host IP address                   : 192.168.1.100  
Gateway IP address                :   
Run from flash/host (f/h)         : f  
Default host run file name        : vmlinux  
Default host flash file name      : bcm963xx_fs_kernel  
Boot delay (0-9 seconds)          : 1  
Board Id (0-11)                   : 963168VXB  
Number of MAC Addresses (1-32)    : 8  
Base MAC Address                  : 5c:f4:ab:17:dc:d0  
PSI Size (1-128) KBytes           : 128  
Enable Backup PSI [0|1]           : 1  
System Log Size (0-256) KBytes    : 0  
Main Thread Number [0|1]          : 0  

*** Press any key to stop auto run (1 seconds) ***
Auto run second count down: 1 1 0

Wait for Multiboot Service Packet...  1 0

Booting from only image (0xb8040000) ...
Code Address: 0x80010000, Entry Address: 0x80330d20
Decompression OK!
Entry at 0x80330d20
Closing network.
Disabling Switch ports.
Flushing Receive Buffers...
0 buffers found.
Closing DMA Channels.
Starting program at 0x80330d20
Linux version 2.6.30 (release@iBuild) (gcc version 4.4.2 (Buildroot 2010.02-git) ) #3 SMP PREEMPT Wed Mar 18 15:05:13 CST 2015
NAND flash device: name <not identified>, id 0x0000 block 128KB size 131072KB
963168VXB prom init
CPU revision is: 0002a080 (Broadcom4350)
DSL SDRAM reserved: 0x132000
Determined physical RAM map:
 memory: 03ece000 @ 00000000 (usable)
Zone PFN ranges:
  DMA      0x00000000 -> 0x00001000
  Normal   0x00001000 -> 0x00003ece
Movable zone start PFN for each node

early_node_map[1] active PFN ranges
    0: 0x00000000 -> 0x00003ece
On node 0 totalpages: 16078

free_area_init_node: node 0, pgdat 8040bc50, node_mem_map 81000000
  DMA zone: 32 pages used for memmap
  DMA zone: 0 pages reserved
  DMA zone: 4064 pages, LIFO batch:0
  Normal zone: 94 pages used for memmap
  Normal zone: 11888 pages, LIFO batch:1

Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 15952
Kernel command line: root=mtd:rootfs ro rootfstype=jffs2 console=ttyS0,115200
wait instruction: enabled
Primary instruction cache 64kB, VIPT, 4-way, linesize 16 bytes.
Primary data cache 32kB, 2-way, VIPT, cache aliases, linesize 16 bytes
NR_IRQS:128
PID hash table entries: 256 (order: 8, 1024 bytes)

console [ttyS0] enabled

Dentry cache hash table entries: 8192 (order: 3, 32768 bytes)
Inode-cache hash table entries: 4096 (order: 2, 16384 bytes)
Memory: 58628k/64312k available (3234k kernel code, 5664k reserved, 863k data, 152k init, 0k highmem)
Calibrating delay loop... 398.33 BogoMIPS (lpj=199168)
Mount-cache hash table entries: 512

--Kernel Config--
  SMP=1
  PREEMPT=1
  DEBUG_SPINLOCK=0
  DEBUG_MUTEXES=0
Broadcom Logger v0.1 Mar 17 2015 17:48:30
CPU revision is: 0002a080 (Broadcom4350)
Primary instruction cache 64kB, VIPT, 4-way, linesize 16 bytes.
Primary data cache 32kB, 2-way, VIPT, cache aliases, linesize 16 bytes
Calibrating delay loop... 402.43 BogoMIPS (lpj=201216)
Brought up 2 CPUs
net_namespace: 1140 bytes
NET: Registered protocol family 16
Internal 1P2 VREG will be shutdown if unused...Unused, turn it off (000088f9-000088f1=8<300)
registering PCI controller with io_map_base unset
registering PCI controller with io_map_base unset
bio: create slab <bio-0> at 0
SCSI subsystem initialized
usbcore: registered new interface driver usbfs
usbcore: registered new interface driver hub
usbcore: registered new device driver usb
pci 0000:00:00.0: reg 10 32bit mmio: [0x10004000-0x10013fff]
pci 0000:00:00.0: supports D1 D2
pci 0000:00:00.0: PME# supported from D0 D3hot D3cold
pci 0000:00:00.0: PME# disabled
pci 0000:00:09.0: reg 10 32bit mmio: [0x10002600-0x100026ff]
pci 0000:00:0a.0: reg 10 32bit mmio: [0x10002500-0x100025ff]
pci 0000:01:00.0: PME# supported from D0 D3hot
pci 0000:01:00.0: PME# disabled
pci 0000:01:00.0: PCI bridge, secondary bus 0000:02
pci 0000:01:00.0:   IO window: disabled
pci 0000:01:00.0:   MEM window: disabled
pci 0000:01:00.0:   PREFETCH window: disabled
PCI: Setting latency timer of device 0000:01:00.0 to 64

skbFreeTask created successfully

BLOG v3.0 Initialized

BLOG Rule v1.0 Initialized

Broadcom IQoS v0.1 Mar 17 2015 17:50:03 initialized
Broadcom GBPM v0.1 Mar 17 2015 17:50:03 initialized

NET: Registered protocol family 8
NET: Registered protocol family 20
NET: Registered protocol family 2
IP route cache hash table entries: 1024 (order: 0, 4096 bytes)
TCP established hash table entries: 2048 (order: 2, 16384 bytes)
TCP bind hash table entries: 2048 (order: 2, 16384 bytes)
TCP: Hash tables configured (established 2048 bind 2048)
TCP reno registered
NET: Registered protocol family 1
JFFS2 version 2.2. (NAND) © 2001-2006 Red Hat, Inc.
fuse init (API version 7.11)
msgmni has been set to 114
io scheduler noop registered (default)
PCI: Setting latency timer of device 0000:01:00.0 to 64
Driver 'sd' needs updating - please use bus_type methods
PPP generic driver version 2.4.2
PPP Deflate Compression module registered
PPP BSD Compression module registered
NET: Registered protocol family 24
Broadcom DSL NAND controller (BrcmNand Controller)
-->brcmnand_scan: CS=0, numchips=1, csi=0
mtd->oobsize=0, mtd->eccOobSize=0
NAND_CS_NAND_XOR=00000000
Disabling XOR on CS#0
brcmnand_scan: Calling brcmnand_probe for CS=0
B4: NandSelect=40000001, nandConfig=15142200, chipSelect=0
brcmnand_read_id: CS0: dev_id=eff18095
After: NandSelect=40000001, nandConfig=15142200
DevId eff18095 may not be supported.  Will use config info
Spare Area Size = 16B/512B
Block size=00020000, erase shift=17
NAND Config: Reg=15142200, chipSize=128 MB, blockSize=128K, erase_shift=11
busWidth=1, pageSize=2048B, page_shift=11, page_mask=000007ff
timing1 not adjusted: 6574845b
timing2 not adjusted: 00001e96
brcmnand_adjust_acccontrol: gAccControl[CS=0]=00000000, ACC=f7ff1010
ECC level changed to 15
OOB size changed to 16
BrcmNAND mfg 0 0 UNSUPPORTED NAND CHIP 128MB on CS0
Found NAND on CS0: ACC=f7ff1010, cfg=15142200, flashId=eff18095, tim1=6574845b, tim2=00001e96
BrcmNAND version = 0x0400 128MB @00000000
brcmnand_scan: Done brcmnand_probe
brcmnand_scan: B4 nand_select = 40000001
brcmnand_scan: After nand_select = 40000001
100 CS=0, chip->ctrl->CS[0]=0
ECC level 15, threshold at 1 bits
reqEccLevel=0, eccLevel=15
190 eccLevel=15, chip->ecclevel=15, acc=f7ff1010
brcmnand_scan 10
200 CS=0, chip->ctrl->CS[0]=0
200 chip->ecclevel=15, acc=f7ff1010
page_shift=11, bbt_erase_shift=17, chip_shift=27, phys_erase_shift=17
brcmnand_scan 220
Brcm NAND controller version = 4.0 NAND flash size 128MB @18000000
brcmnand_scan 230
brcmnand_scan 40, mtd->oobsize=64, chip->ecclayout=00000000
brcmnand_scan 42, mtd->oobsize=64, chip->ecclevel=15, isMLC=0, chip->cellinfo=0
ECC layout=brcmnand_oob_bch4_4k
brcmnand_scan:  mtd->oobsize=64
brcmnand_scan: oobavail=50, eccsize=512, writesize=2048
brcmnand_scan, eccsize=512, writesize=2048, eccsteps=4, ecclevel=15, eccbytes=3
300 CS=0, chip->ctrl->CS[0]=0
500 chip=83a47990, CS=0, chip->ctrl->CS[0]=0

-->brcmnand_default_bbt

brcmnand_default_bbt: bbt_td = bbt_main_descr
Bad block table Bbt0 not found for chip on CS0
Bad block table 1tbB not found for chip on CS0

File system address: 0xb8040000
Scanning device for bad blocks, options=00004000
-->brcmnand_isbad_raw(offs=7fe0000
Bad block table written to 0x07fe0000, version 0x01
-->brcmnand_isbad_raw(offs=7fc0000
Bad block table written to 0x07fc0000, version 0x01
rescanning .... 

----- Contents of BBT -----

----- END Contents of BBT -----

brcmnandCET: Did not find CET, recreating
brcmnandCET: Status -> Deferred
brcmnand_scan 99

Root file system size 28e0000

Creating 4 MTD partitions on "brcmnand.0":
0x000000040000-0x000001160000 : "rootfs"
0x0000051e0000-0x0000055e0000 : "data"
0x000000000000-0x000000020000 : "nvram"
0x0000055e0000-0x000007f00000 : "fw"

ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
PCI: Enabling device 0000:00:0a.0 (0000 -> 0002)
PCI: Setting latency timer of device 0000:00:0a.0 to 64
ehci_hcd 0000:00:0a.0: EHCI Host Controller
ehci_hcd 0000:00:0a.0: new USB bus registered, assigned bus number 1
ehci_hcd 0000:00:0a.0: Enabling legacy PCI PM
ehci_hcd 0000:00:0a.0: irq 18, io mem 0x10002500
ehci_hcd 0000:00:0a.0: USB f.f started, EHCI 1.00
usb usb1: configuration #1 chosen from 1 choice
hub 1-0:1.0: USB hub found
hub 1-0:1.0: 2 ports detected
ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
PCI: Enabling device 0000:00:09.0 (0000 -> 0002)
PCI: Setting latency timer of device 0000:00:09.0 to 64
ohci_hcd 0000:00:09.0: OHCI Host Controller
ohci_hcd 0000:00:09.0: new USB bus registered, assigned bus number 2
ohci_hcd 0000:00:09.0: irq 17, io mem 0x10002600
usb usb2: configuration #1 chosen from 1 choice
hub 2-0:1.0: USB hub found
hub 2-0:1.0: 2 ports detected
usbcore: registered new interface driver usblp
Initializing USB Mass Storage driver...
usbcore: registered new interface driver usb-storage
USB Mass Storage support registered.
Watchdog Timer Init -- kthread
brcmboard: brcm_board_init entry
SES: Button Interrupt 0x1 is enabled
SES: LED GPIO 0x10 is enabled
PCIe: No device found - Powering down
Serial: BCM63XX driver $Revision: 3.00 $
Magic SysRq enabled (type ^ h for list of supported commands)
ttyS0 at MMIO 0xb0000180 (irq = 13) is a BCM63XX
ttyS1 at MMIO 0xb00001a0 (irq = 42) is a BCM63XX
Total # RxBds=1448
bcmPktDmaBds_init: Broadcom Packet DMA BDs initialized
bcmPktDma_init: Broadcom Packet DMA Library initialized
bcmxtmrt: Broadcom BCM3168D0 ATM/PTM Network Device v0.4 Mar 17 2015 17:49:53
p8021ag: p8021ag_init entry
IPSEC SPU: SUCCEEDED 
GACT probability NOT on
Mirror/redirect action on
u32 classifier
    input device check on 
    Actions configured 
TCP cubic registered
Initializing XFRM netlink socket
NET: Registered protocol family 10
IPv6 over IPv4 tunneling driver
NET: Registered protocol family 17
NET: Registered protocol family 15
Initializing MCPD Module
Ebtables v2.0 registered
ebt_time registered
ebt_ftos registered
ebt_wmm_mark registered
802.1Q VLAN Support v1.8 Ben Greear <greearb@candelatech.com>
All bugs added by David S. Miller <davem@redhat.com>
VFS: Mounted root (jffs2 filesystem) readonly on device 31:0.
Freeing unused kernel memory: 152k freed
Empty flash at 0x00372e80 ends at 0x00373000
Empty flash at 0x00378ec8 ends at 0x00379000

cp: can't stat '/etc/samba/samba': No such file or directory
mkdir: can't create directory '/var/etc': File exists
cp: can't stat '/etc/ppp/chat/*': No such file or directory
mkdir: can't create directory '/var/etc': File exists
Loading drivers and kernel modules... 
JFFS2 notice: (225) check_node_data: wrong data CRC in data node at 0x00377e84: read 0xeaa0c7e7, calculated 0x9f161909.
chipinfo: module license 'proprietary' taints kernel.
Disabling lock debugging due to kernel taint
brcmchipinfo: brcm_chipinfo_init entry
Broadcom Ingress QoS Module  Char Driver v0.1 Mar 17 2015 17:48:51 Registered<243>
Broadcom Ingress QoS ver 0.1 initialized
BPM: tot_mem_size=67108864B (64MB), buf_mem_size=10066320B (9MB), num of buffers=4730, buf size=2128
Broadcom BPM Module Char Driver v0.1 Mar 17 2015 17:48:47 Registered<244>
[NTC bpm] bpm_set_status: BPM status : enabled 

NBUFF v1.0 Initialized

Initialized fcache state
Broadcom Packet Flow Cache  Char Driver v2.2 Mar 17 2015 17:48:51 Registered<242>
Created Proc FS /procfs/fcache
Broadcom Packet Flow Cache registered with netdev chain
Broadcom Packet Flow Cache learning via BLOG enabled.
Constructed Broadcom Packet Flow Cache v2.2 Mar 17 2015 17:48:51

chipId 0x631680D0
Broadcom Forwarding Assist Processor (FAP) Char Driver v0.1 Mar 17 2015 17:48:47 Registered <241>
Enabling SMISBUS PHYS_FAP_BASE[0] is 0x10c01000
FAP Soft Reset Done
4ke Reset Done
Enabling SMISBUS PHYS_FAP_BASE[1] is 0x10c01000
FAP Soft Reset Done
4ke Reset Done
FAP Debug values at 0xa241cf90 0xa249cf90
Allocated FAP0 GSO Buffers (0xA242E018) : 1048576 bytes @ 0xA2500000
Allocated FAP1 GSO Buffers (0xA24AE018) : 1048576 bytes @ 0xA2600000
Allocated FAP0 TM SDRAM Queue Storage (a242e01c) : 341376 bytes @ a2700000
Allocated FAP1 TM SDRAM Queue Storage (a24ae01c) : 341376 bytes @ a2780000
[NTC fapProto] fapReset  : Reset FAP Protocol layer
fapDrv_construct: FAP0: pManagedMemory=b0820650. wastage 8 bytes
fapDrv_construct: FAP1: pManagedMemory=b0a20650. wastage 8 bytes
bcmPktDma_bind: FAP Driver binding successfull
[FAP0] DSPRAM : stack <0x80000000><1536>, global <0x80000600><3960>, free <2696>, total<8192>
[FAP1] DSPRAM : stack <0x80000000><1536>, global <0x80000600><3960>, free <2696>, total<8192>
[FAP0] PSM : addr<0x80002000>, used <23436>, free <1140>, total <24576>
[FAP1] PSM : addr<0x80002000>, used <23436>, free <1140>, total <24576>
[FAP0] DQM : availableMemory 14652 bytes, nextByteAddress 0xE0004948
[FAP1] DQM : availableMemory 14652 bytes, nextByteAddress 0xE0004948
[FAP0] GSO Buffer set to 0xA2500000
[FAP1] GSO Buffer set to 0xA2600000
[FAP0] FAP BPM Initialized.
[FAP1] FAP BPM Initialized.
[FAP0] FAP TM: ON
[FAP1] FAP TM: ON

bcmxtmcfg: bcmxtmcfg_init entry
adsl: adsl_init entry

Broadcom BCM63168D0 Ethernet Network Device v0.1 Mar 17 2015 17:49:50

fapDrv_psmAlloc: fapIdx=0, size: 4800, offset=b0820650 bytes remaining 7000
ETH Init: Ch:0 - 200 tx BDs at 0xb0820650
fapDrv_psmAlloc: fapIdx=1, size: 4800, offset=b0a20650 bytes remaining 7000
ETH Init: Ch:1 - 200 tx BDs at 0xb0a20650
fapDrv_psmAlloc: wastage 8 bytes
fapDrv_psmAlloc: fapIdx=0, size: 4808, offset=b0821910 bytes remaining 2184
ETH Init: Ch:0 - 600 rx BDs at 0xb0821910
fapDrv_psmAlloc: wastage 8 bytes
fapDrv_psmAlloc: fapIdx=1, size: 4808, offset=b0a21910 bytes remaining 2184
ETH Init: Ch:1 - 600 rx BDs at 0xb0a21910
dgasp: kerSysRegisterDyingGaspHandler: bcmsw registered 
eth2: MAC Address: 5C:F4:AB:17:DC:D0
eth1: MAC Address: 5C:F4:AB:17:DC:D0
eth0: MAC Address: 5C:F4:AB:17:DC:D0
eth3: MAC Address: 5C:F4:AB:17:DC:D0
eth4: MAC Address: 5C:F4:AB:17:DC:D0
eth4 Link UP 1000 mbps full duplex

message received before monitor task is initialized kerSysSendtoMonitorTask 

Broadcom BCM3168D0 USB Network Device v0.4a Mar 17 2015 17:48:55
usb0: MAC Address: 5C F4 AB 17 DC D1
usb0: Host MAC Address: 5C F4 AB 17 DC D2
hub 1-0:1.0: over-current change on port 2
USBD Initialization done status 0 
[NTC arl] arlEnable : Enabled ARL binding to FAP

USB Link DOWN.

message received before monitor task is initialized kerSysSendtoMonitorTask 
Broadcom Address Resolution Logic Processor (ARL) Char Driver v0.1 Mar 17 2015 17:48:46 Registered <245>

--SMP support

wl: dsl_tx_pkt_flush_len=338
wl: high_wmark_tot=3074
PCI: Setting latency timer of device 0000:00:00.0 to 64
wl: passivemode=1
wl: napimode=0
wl0: allocskbmode=1 currallocskbsz=256
Neither SPROM nor OTP has valid image
wl:srom/otp not programmed, using main memory mapped srom info(wombo board)
wl:loading /etc/wlan/bcm6362_map.bin
srom rev:8
wl: reading /etc/wlan/bcmcmn_nvramvars.bin, file size=32
wl0: Broadcom BCM435f 802.11 Wireless Controller 6.30.102.7.cpe4.12L08.4
dgasp: kerSysRegisterDyingGaspHandler: wl0 registered 

Broadcom 802.1Q VLAN Interface, v0.1
[2]+  Done(1)                    test -e /bin/icf.exe && /bin/icf.exe
[1]+  Done(1)                    test -e /bin/mm.exe && /bin/mm.exe

===== Release Version 4.12L.08 (build timestamp 150318_1505) =====

Thu Jan  1 00:00:00 UTC 2015
open /var/log/email_settings fail
Host MIPS Clock divider pwrsaving is enabled
DDR Self Refresh pwrsaving is enabled
Energy Efficient Ethernet is disabled

Sntp: Using new rule CET-1CEST,M3.5.0/3:0,M10.5.0/2:0
ip_tables: (C) 2000-2006 Netfilter Core Team
ip6_tables: (C) 2000-2006 Netfilter Core Team

rm: can't remove '/var/vsftpd_user_conf/*': No such file or directory
ssk:error:29.978:rcl_ipv6LanIntfAddrObject:93:invalid ULA address: (null)
ssk:error:29.979:mdm_activateObjects:918:rcl handler reports error=9007 on X_TELEFONICA-ES_IPv6LanIntfAddress {1,2}

device eth0 entered promiscuous mode

dhcpd:error:30.379:set_iface_config_defaults:627:SIOCGIFADDR failed on br0!
RTNETLINK answers: File exists
ADDRCONF(NETDEV_UP): eth0: link is not ready
Success 
Success 
Success 
Success 
Success 
device eth2 entered promiscuous mode
RTNETLINK answers: File exists
ADDRCONF(NETDEV_UP): eth2: link is not ready
Success 
Success 
Success 
Success 
Success 
device eth3 entered promiscuous mode
RTNETLINK answers: File exists
ADDRCONF(NETDEV_UP): eth3: link is not ready
Success 
Success 
Success 
Success 
Success 
device eth1 entered promiscuous mode
RTNETLINK answers: File exists
ADDRCONF(NETDEV_UP): eth1: link is not ready
Success 
Success 
Success 
Success 
Success 
*** dslThread dslPid=1286
BcmAdsl_Initialize=0xC026FB70, g_pFnNotifyCallback=0xC02AC8F4
WLmngr Daemon is running
optarg=0 shmId=0 
wlevt is ready for new msg...
lmemhdr[2]=0x100CE000, pAdslLMem[2]=0x100CE000
pSdramPHY=0xA3FFFFF8, 0x1B7BFC 0xDEADBEEF
*** XfaceOffset: 0x5FF90 => 0x5FF90 ***
*** PhySdramSize got adjusted: 0xDACE8 => 0x111500 ***
AdslCoreSharedMemInit: shareMemSize=133853(133856)
AdslCoreHwReset:  pLocSbSta=80e80000 bkupThreshold=3072
AdslCoreHwReset:  AdslOemDataAddr = 0xA3F9A5F4

***BcmDiagsMgrRegisterClient: 0 ***

dgasp: kerSysRegisterDyingGaspHandler: dsl0 registered 

ssk:error:39.935:xdslCtl_Initialize:340:ADSL drivfapDrv_psmAlloc: fapIdx=1, size: 1600, offset=b0a22be0 bytes remaining 584
er ADSLIOCTL_SETXTM Init: Ch:0 - 200 rx BDs at 0xb0a22be0

_OEM_PARAM ADSL_fapDrv_psmAlloc: fapIdx=1, size: 128, offset=b0a23220 bytes remaining 456
OEM_EOC_VENDOR_IXTM Init: Ch:1 - 16 rx BDs at 0xb0a23220

D success

ssk:error:39.936:xdbcmxtmrt: PTM/ATM Non-Bonding Mode configured in system 

slCtl_Initialize:382:serialNumber = 5C:F4:AB:17:DC:D0
ssk:error:39.936:xdslCtl_Initialize:392:ADSL driver ADSLIOCTL_SET_OEM_PARAM ADSL_OEM_EOC_SERIAL_NUMBER success
ssk:error:39.936:xdslCtl_Initialize:395:version = 20150318
ssk:error:39.936:xdslCtl_Initialize:405:ADSL driver ADSLIOCTL_SET_OEM_PARAM ADSL_OEM_EOC_VERSION success

iptables v1.4.0: can't initialize iptables table `nat': Table does not exist (do you need to insmod?)
Perhaps iptables or your kernel needs to be upgraded.
iptables: No chain/target/match by that name
iptables: No chain/target/match by that name
iptables v1.4.0: can't initialize iptables table `nat': Table does not exist (do you need to insmod?)
Perhaps iptables or your kernel needs to be upgraded.
iptables: No chain/target/match by that name
iptables: No chain/target/match by that name
iptables v1.4.0: can't initialize iptables table `nat': Table does not exist (do you need to insmod?)
Perhaps iptables or your kernel needs to be upgraded.
iptables: No chain/target/match by that name
iptables: No chain/target/match by that name
iptables v1.4.0: can't initialize iptables table `nat': Table does not exist (do you need to insmod?)
Perhaps iptables or your kernel needs to be upgraded.
iptables: No chain/target/match by that name
iptables: No chain/target/match by that name
iptables v1.4.0: can't initialize iptables table `nat': Table does not exist (do you need to insmod?)
Perhaps iptables or your kernel needs to be upgraded.
iptables: No chain/target/match by that name
iptables: No chain/target/match by that name
iptables v1.4.0: can't initialize iptables table `nat': Table does not exist (do you need to insmod?)
Perhaps iptables or your kernel needs to be upgraded.
iptables: No chain/target/match by that name
iptables: No chain/target/match by that name
iptables v1.4.0: can't initialize iptables table `nat': Table does not exist (do you need to insmod?)
Perhaps iptables or your kernel needs to be upgraded.
iptables: No chain/target/match by that name
iptables: No chain/target/match by that name
WLMNGR-DAEMON:error:44.018:dumpLockInfo:68:locked=[1] lockOwner=[295]
WLMNGR-DAEMON:error:44.018:dumpLockInfo:74:held for 17461ms by function cmsMdm_init
Could not get lock!
sh: can't open /var/cert/G3.cacert: no such file
sh: can't open /var/cert/G2.cacert: no such file
sh: can't open /var/cert/G1.cacert: no such file
sh: can't open /var/cert/G2.cacert: no such file
sh: can't open /var/cert/G1.cacert: no such file
sh: can't open /var/cert/G1.cacert: no such file
[ifconfig eth4 up]
[brctl addif br0 eth4]
device eth4 entered promiscuous mode

br0: port 5(eth4) entering forwarding state

nf_conntrack version 0.5.0 (1024 buckets, 4096 max)

iptables: Bad rule (does a matching rule exist in that chain?)
ip6tables: Bad rule (does a matching rule exist in that chain?)
iptables: No chain/target/match by that name
iptables: No chain/target/match by that name
iptables: No chain/target/match by that name
ip6tables: No chain/target/match by that name
ip6tables: No chain/target/match by that name
There is no Predefined DevicePin in CFE
WPS Device PIN = 78023796
Setting SSID: "Internet_D0"
Setting SSID: "SSID2"
Setting SSID: "SSID3"
Setting SSID: "SSID4"
Enter user spaceStarting celld daemon......
ssk:error:54.594:rutWan_startL3Interface:557:L2IfName usb1 is not up
ssk:error:54.594:rutCfg_startWanIpConnection:114:rutWan_startL3Interface failed. error=9002
ssk:error:54.594:rcl_wanIpConnObject:752:rutCfg_startWanIpConnection failed, error 9002
ssk:error:54.708:updateSingleWanConnStatusLocked:2158:Fail to set wanConnObj. ret=9002
ssk:error:55.583:rutWan_startL3Interface:557:L2IfName eth5 is not up
ssk:error:55.583:rutCfg_startWanIpConnection:114:rutWan_startL3Interface failed. error=9002
ssk:error:55.583:rcl_wanIpConnObject:752:rutCfg_startWanIpConnection failed, error 9002
ssk:error:55.654:updateSingleWanConnStatusLocked:2158:Fail to set wanConnObj. ret=9002

celld:error:145.588:lck_checkBeforeEntry:206:lock required during cmsObj_getNextInSubTreeFlags
celld:error:145.589:lck_checkBeforeEntry:206:lock required during cmsObj_getNextInSubTreeFlags
celld:error:145.589:lck_checkBeforeEntry:206:lock required during cmsObj_getNextInSubTreeFlags
celld:error:145.589:lck_checkBeforeEntry:206:lock required during cmsObj_getNextInSubTreeFlags

head: /tmp/usb-get-ids.out: No such file or directory
head: /tmp/usb-get-ids.out: No such file or directory
head: /tmp/usb-get-ids.out: No such file or directory
rmmod: can't unload 'option': unknown symbol in module, or unknown parameter
rmmod: can't unload 'sierra': unknown symbol in module, or unknown parameter
rmmod: can't unload 'usbserial': unknown symbol in module, or unknown parameter
rmmod: can't unload 'lg_vl600': unknown symbol in module, or unknown parameter
rmmod: can't unload 'cdc_acm': unknown symbol in module, or unknown parameter
rmmod: can't unload 'hso': unknown symbol in module, or unknown parameter
head: /tmp/usb-get-ids.out: No such file or directory
head: /tmp/usb-get-ids.out: No such file or directory
head: /tmp/usb-get-ids.out: No such file or directory
head: /tmp/usb-get-ids.out: No such file or directory
head: /tmp/usb-get-ids.out: No such file or directory
head: /tmp/usb-get-ids.out: No such file or directory
mwan: Mobile WAN adapter detected: Linux 2.6.30 ohci_hcd
Linux 2.6.30 ehci_hcd OHCI Host Controller
EHCI Host Controller (:)
usbserial: `0x' invalid for parameter `vendor'

insmod: can't insert '/lib/modules/2.6.30/kernel/drivers/usb/serial/usbserial.ko': Invalid argument

ZyXEL VDSL Router
Login: admin
Password:

```

[Main Page](README.md)