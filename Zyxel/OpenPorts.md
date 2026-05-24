[Main Page](README.md)

#Open ports

##Port scan
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-11 18:47 CET
Nmap scan report for Broadcom.Home (10.10.10.1)
Host is up (0.0037s latency).
Not shown: 996 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
23/tcp open  telnet
80/tcp open  http
```

##Netstat

```
 > echo $(netstat -tupln)
Active Internet connections (only servers) Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name tcp 0 0 10.10.10.1:1990 0.0.0.0:* LISTEN 2624/wps_monitor 
tcp 0 0 0.0.0.0:44401 0.0.0.0:* LISTEN 292/smd 
tcp 0 0 0.0.0.0:21 0.0.0.0:* LISTEN 292/smd 
tcp 0 0 0.0.0.0:5916 0.0.0.0:* LISTEN 2622/acsd 
tcp 0 0 :::80 :::* LISTEN 292/smd 
tcp 0 0 :::22 :::* LISTEN 292/smd 
tcp 0 0 :::23 :::* LISTEN 292/smd 
tcp 0 0 :::7547 :::* LISTEN 292/smd 
udp 0 0 0.0.0.0:51333 0.0.0.0:* 292/smd 
udp 0 0 0.0.0.0:37000 0.0.0.0:* 2560/eapd 
udp 0 0 127.0.0.1:38032 0.0.0.0:* 2564/nas 
udp 0 0 0.0.0.0:42000 0.0.0.0:* 2560/eapd 
udp 0 0 127.0.0.1:42032 0.0.0.0:* 2622/acsd 
udp 0 0 127.0.0.1:40500 0.0.0.0:* 2624/wps_monitor 
udp 0 0 0.0.0.0:67 0.0.0.0:* 2351/dhcpd 
udp 0 0 127.0.0.1:37064 0.0.0.0:* 2624/wps_monitor 
udp 0 0 0.0.0.0:50000 0.0.0.0:* 2560/eapd 
udp 0 0 0.0.0.0:5098 0.0.0.0:* 2172/dsldiagd 
udp 0 0 0.0.0.0:5099 0.0.0.0:* 2172/dsldiagd 
udp 0 0 0.0.0.0:1900 0.0.0.0:* 2624/wps_monitor 
udp 0 0 0.0.0.0:5100 0.0.0.0:* 2172/dsldiagd 
udp 0 0 0.0.0.0:38000 0.0.0.0:* 2560/eapd 
udp 0 0 0.0.0.0:50032 0.0.0.0:* 1234/wlevt 
udp 0 0 0.0.0.0:43000 0.0.0.0:* 2560/eapd 
udp 0 0 :::547 :::* 2532/dhcp6s 
udp 0 0 :::53 :::* 311/dnsproxy 
udp 0 0 :::69 :::* 292/smd 
udp 0 0 :::19401 :::* 311/dnsproxy 
udp 0 0 :::48587 :::* 2532/dhcp6s 
udp 0 0 :::56956 :::* 311/dnsproxy
```

## inetd

```
cat /etc/inetd.conf
echo    stream  tcp     nowait  root    internal
echo    dgram   udp     wait    root    internal
discard stream  tcp     nowait  root    internal
discard dgram   udp     wait    root    internal
daytime stream  tcp     nowait  root    internal
daytime dgram   udp     wait    root    internal
chargen stream  tcp     nowait  root    internal
chargen dgram   udp     wait    root    internal
time    stream  tcp     nowait  root    internal
time    dgram   udp     wait    root    internal
ftp     stream  tcp     nowait  root    /bin/ftpd ftpd
telnet  stream  tcp     nowait  root    /bin/telnetd telnetd -L /bin/login
```

[Main Page](README.md)