[Main Page](../../README.md)

# SubGHzMorseMessage

SubGHz Morse Message transmitter.
Converts A-Z, digits 0-9, and spaces to Morse, then sends raw OOK timing pulses.
Frequency is entered in MHz; dot time is entered in milliseconds.
Defaults: 449.81 MHz, 120 ms dot, message "test", and 0 MHz frequency correction.
JSON settings are loaded from SD:/jsApps/config/SubGHzMorseMesssage.conf.
The correction is read only from config and added to the entered frequency.
A missing config file is created with defaults; existing config is not overwritten.
Tested with a LilyGo T-Embed + CC1101 running Bruce 1.16.1.

Also output all info in console log, which can be seen in serial console.

Frequency correction: during testing on my LilyGo T-Embed + CC1101 i find that it add 54kHz
In config I have set this to -0.054 and it works perfectly. I used SDR to measure it.

[Main Page](../../README.md)