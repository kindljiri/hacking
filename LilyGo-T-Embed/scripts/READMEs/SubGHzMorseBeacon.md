[Main Page](../../README.md)

# SubGHzMorseMessage

SubGHz Morse Beacon transmitter.
Converts A-Z, digits 0-9, and spaces to Morse, then sends raw OOK timing pulses.
Startup prompts accept frequency in MHz, dot time in milliseconds, and resend delay in seconds.
Config defaults: 449.81 MHz, 120 ms dot, 10 s resend delay, message "test", and 0 MHz correction.
JSON settings are loaded from SD:/jsApps/config/SubGHzMorseBeacon.conf.
Config keys: frequencyMHz, frequencyCorrectionMHz, dotTimeMs, resendDelaySeconds, and message.
frequencyCorrectionMHz is config-only and is added to the prompted frequency.
Prompted values override defaults for this run; they are not saved to an existing config file.
A missing config file is created with defaults; an existing config file is not overwritten.
Tested with a LilyGo T-Embed + CC1101 running Bruce 1.16.1.

Also output all info in console log, which can be seen in serial console.

Frequency correction: during testing on my LilyGo T-Embed + CC1101 i find that it add 54kHz
In config I have set this to -0.054 and it works perfectly. I used SDR to measure it.

[Main Page](../../README.md)