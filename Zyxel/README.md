Those are notes from my "hacking" off Zyxel ADD MODEL HERE

I have the admin password so it will not cover the way to get it.

By doing the [portscan](OpenPorts.md) and openning the device there are two ways in:
- Telnet
- [UART](UART.md)

As we know the user is admin and we got the password we can start obtaining info:
- [Versions](Versions.md)
- Hardware info 
- [Boot output from UART](BootOutput.md)
- Available Commands

As we have avalable just limit set of commands, but we know there is BusyBox our goal is to get full shell.