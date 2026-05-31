

```
~ # ps
  PID USER       VSZ STAT COMMAND
    1 support   2112 S    init
    2 support      0 SW<  [kthreadd]
    3 support      0 SW<  [migration/0]
    4 support      0 SW   [sirq-high/0]
    5 support      0 SW   [sirq-timer/0]
    6 support      0 SW   [sirq-net-tx/0]
    7 support      0 SW   [sirq-net-rx/0]
    8 support      0 SW   [sirq-block/0]
    9 support      0 SW   [sirq-tasklet/0]
   10 support      0 SW   [sirq-sched/0]
   11 support      0 SW   [sirq-hrtimer/0]
   12 support      0 SW   [sirq-rcu/0]
   13 support      0 SW<  [migration/1]
   14 support      0 SW   [sirq-high/1]
   15 support      0 SW   [sirq-timer/1]
   16 support      0 SW   [sirq-net-tx/1]
   17 support      0 SW   [sirq-net-rx/1]
   18 support      0 SW   [sirq-block/1]
   19 support      0 SW   [sirq-tasklet/1]
   20 support      0 SW   [sirq-sched/1]
   21 support      0 SW   [sirq-hrtimer/1]
   22 support      0 SW   [sirq-rcu/1]
   23 support      0 SW<  [events/0]
   24 support      0 SW<  [events/1]
   25 support      0 SW<  [khelper]
   28 support      0 SW<  [async/mgr]
   75 support      0 SW<  [kblockd/0]
   76 support      0 SW<  [kblockd/1]
   85 support      0 SW<  [khubd]
  102 support      0 SW<  [skbFreeTask]
  103 support      0 SW<  [bpm]
  119 support      0 SW   [pdflush]
  120 support      0 SW   [pdflush]
  121 support      0 SWN  [kswapd0]
  123 support      0 SW<  [crypto/0]
  124 support      0 SW<  [crypto/1]
  181 support      0 SW<  [mtdblockd]
  212 support      0 SW<  [watchdog_thread]
  216 support      0 SW<  [linkwatch]
  245 support      0 SWN  [jffs2_gcd_mtd1]
  246 support      0 SWN  [jffs2_gcd_mtd3]
  262 support   2136 S    -/bin/sh
  279 support      0 SW   [kpAliveWatchdog]
  293 support      0 SW   [bcmsw]
  294 support      0 SW   [bcmsw_timer]
  312 support   6736 S    smd
  315 support   7376 S    ssk
  316 support   2108 S    tftpd
  323 support   2124 S    syslogd -n -C -l 1
  324 support   2104 S    klogd -n
  331 support   1452 S    dnsproxy
  333 support   1408 S    sntp -s ntp.o2isp.cz -s (null) -t CET-1CEST,M3.5.0/3
  532 support   7660 S    mcpd -m 0
 1197 support   8472 S    wlmngr -m 0
 1258 support   1396 S    /bin/wlevt
 1347 support      0 SW   [dsl0]
 1723 support   4412 S    vsftpd
 2010 support   7724 S N  smbd -D -s /etc/samba/smb.conf -l=/var/tmp/smbvar --
 2171 support   7724 S N  smbd -D -s /etc/samba/smb.conf -l=/var/tmp/smbvar --
 2199 support    812 S    cpuload
 2200 support   1508 S    dsldiagd
 2201 support      0 Z    [smd]
 2202 support   6124 S    link_updown
 2203 support   8760 S    celld -m 0
 2377 support   1648 S    dhcpd
 2559 support   1216 S    radvd -C /var/radvd.conf
 2560 support   1872 S    dhcp6s -c /var/dhcp6s.conf br0
 2584 support   1304 S    /bin/lld2d br0
 2588 support   1240 S    /bin/eapd
 2592 support   1592 S    /bin/nas
 2603 support   1312 S    /bin/acsd
 2606 support   2796 S    /bin/wps_monitor
 2793 support      0 SW<  [scsi_eh_1]
 2794 support      0 SW<  [usb-storage]
 2846 support   7472 S    telnetd -m 0
 2847 support   7476 S    telnetd -m 0
 2870 support   2108 S    sh -c sh
 2871 support   2124 S    sh
 2932 support   2112 R    ps
```
