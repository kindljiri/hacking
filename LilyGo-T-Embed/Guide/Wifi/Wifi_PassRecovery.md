[Main Page](../../README.md)

# Wifi Password Recovery

First we need to capture some handshakes.
- Under Wifi Atks pick Target Atks

![Wifi_PassRecovery_01](Wifi_PassRecovery_01.jpg)
![Wifi_PassRecovery_02](Wifi_PassRecovery_02.jpg)
![Wifi_PassRecovery_03](Wifi_PassRecovery_03.jpg)
- Choose SSID

![Wifi_PassRecovery_04](Wifi_PassRecovery_04.jpg)
- Capture Handshake and wait

![Wifi_PassRecovery_05](Wifi_PassRecovery_05.jpg)
- You can press Mid button to deauth which will force client to reconnect and you got handshake.

![Wifi_PassRecovery_06](Wifi_PassRecovery_06.jpg)
- And eventually ...

![Wifi_PassRecovery_07](Wifi_PassRecovery_07.jpg)

Once we have captured the packets we need we can try recover it using wordlist.
![Wifi_PassRecovery_08](Wifi_PassRecovery_08.jpg)
- Pick the wordlist
![Wifi_PassRecovery_09](Wifi_PassRecovery_09.jpg)
- Then the pcap file with hanshake we captured previously
![Wifi_PassRecovery_10](Wifi_PassRecovery_10.jpg)
![Wifi_PassRecovery_11](Wifi_PassRecovery_11.jpg)
- Pick the SSID
![Wifi_PassRecovery_12](Wifi_PassRecovery_12.jpg)
- Wait and pray
![Wifi_PassRecovery_13](Wifi_PassRecovery_13.jpg)
- And if you lucky enough, or admin is lazy ...
![Wifi_PassRecovery_14](Wifi_PassRecovery_14.jpg)


[Main Page](../../README.md)