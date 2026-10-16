[Main Page](../../README.md)

# IrAnalyzerSerial

Serial-based infrared protocol analyzer for LilyGo T-Embed / M5 Cardputer.
It captures IR timings from the built-in IR sensor, prints a timing histogram, and tries to match the signal against a set of known IR protocols.

Tested with M5 Cardputer + IR Remote and the Bruce firmware environment.

## What it does

The script provides a small menu-driven analyzer:

- Raw mode: captures a raw IR recording and analyzes it.
- Automatic mode: waits for a signal, then offers retry / menu / exit.
- Settings: lets you change the receive timeout.
- Exit: quits the application.

The analyzer reads the raw data line from the IR library, extracts timing values, builds a histogram, and compares the result with known timing profiles.

## Menu flow

When the app starts, it shows:

- `1) Raw`
- `2) Automatic`
- `3) Settings`
- `4) Exit`

The raw mode path:

1. Capture signal with `ir.readRaw(timeout)`
2. Print the raw data
3. Compute histogram of timings
4. Match against known protocols
5. Print the result and canonical header info

The automatic mode path:

1. Capture signal with `ir.read(timeout)`
2. Print the captured signal
3. Offer retry or menu exit

## Configuration file

The analyzer attempts to load custom protocol definitions from:

- `SD:/jsApps/config/KNOWN_PROTOCOLS.conf`

The script does this internally via:

```javascript
var configPath = {
    fs: "sd",
    path: "/jsApps/config/KNOWN_PROTOCOLS.conf"
};
```

If the file is missing, invalid, or malformed, the script falls back to the built-in profiles in `KNOWN_PROTOCOLS`.

## Config file format

The config file is not CSV and not a simple key-value text file. It must be valid JSON containing an array of protocol arrays.

Example:

```json
[
  ["NEC", "PULSE_DISTANCE", 9000, 4500, 560, 560, 1690, 40000, 32],
  ["SAMSUNG", "PULSE_DISTANCE", 4500, 4500, 560, 560, 1690, 40000, 32],
  ["SONY_SIRC", "PULSE_WIDTH", 2400, 600, 600, 600, 1200, 25000, 12],
  ["PANASONIC", "PULSE_DISTANCE", 3500, 1750, 430, 430, 1300, 10000, 48],
  ["RC6_MODE0", "MANCHESTER", 2666, 889, 444, 0, 0, 10000, 20]
]
```

### Row layout

Each row has exactly 9 values:

1. `name` — protocol name, string
2. `type` — one of:
   - `"PULSE_DISTANCE"`
   - `"PULSE_WIDTH"`
   - `"MANCHESTER"`
3. `headerMark` — first header pulse length in microseconds
4. `headerSpace` — first header gap length in microseconds
5. `bitMark` — short-bit timing mark in microseconds
6. `zeroSpace` — space used for zero bit
7. `oneSpace` — space used for one bit
8. `eopGap` — end-of-packet gap in microseconds
9. `totalBits` — expected bit count

### Notes

- The file must contain between 1 and 31 entries.
- All numeric values must be finite numbers.
- The comment at the top of the JS file is only documentation:

```javascript
// name,type,headerMark,headerSpace,bitMark,zeroSpace,oneSpace,eopGap,totalBits
```

This comment does not define a real file format by itself. The actual valid format is JSON.

## Example custom config

A minimal custom config containing one profile:

```json
[
  ["MY_PROTOCOL", "PULSE_DISTANCE", 9000, 4500, 560, 560, 1690, 40000, 32]
]
```

This is valid as long as the values match the IR waveform you want to classify.

## Built-in protocol list

The script includes these default protocol definitions:

```javascript
var KNOWN_PROTOCOLS = [
    ["NEC", "PULSE_DISTANCE", 9000, 4500, 560, 560, 1690, 40000, 32],
    ["SAMSUNG", "PULSE_DISTANCE", 4500, 4500, 560, 560, 1690, 40000, 32],
    ["SONY_SIRC", "PULSE_WIDTH", 2400, 600, 600, 600, 1200, 25000, 12],
    ["PANASONIC", "PULSE_DISTANCE", 3500, 1750, 430, 430, 1300, 10000, 48],
    ["PIONEER", "PULSE_DISTANCE", 8400, 4200, 500, 500, 1500, 25000, 32],
    ["RC6_MODE0", "MANCHESTER", 2666, 889, 444, 0, 0, 10000, 20]
];
```

## How matching works

The script does the following:

1. Reads raw signal timings from the `data:` section.
2. Converts the values into a duration histogram using a configurable bin size.
3. Checks if the histogram contains the canonical header timings.
4. Checks whether the bit timings match the expected protocol type.
5. Reports either:
   - `Matched Protocol`
   - `Single Histogram Match`
   - `Unknown Protocol`

## Example output

```text
=== TIMING DISTRIBUTION ===
560 µs [32]: #######
9000 µs [1]: #
4500 µs [1]: #
...
----------------------------------------
PROTOCOL IDENTIFICATION RESULT
----------------------------------------
Matched Protocol : NEC
Header Verification : CONFIRMED
Canonical Header   : Mark 9000 us, Space 4500 us
Encoding Scheme    : PULSE_DISTANCE
Expected Bit Count : 32
----------------------------------------
```

## Files involved

- `scripts/IrAnalyzerSerial.js` — main analyzer script
- `SD:/jsApps/config/KNOWN_PROTOCOLS.conf` — optional custom protocol definitions

## Practical usage

1. Copy the analyzer script to the device environment.
2. Put a valid JSON protocol file at `SD:/jsApps/config/KNOWN_PROTOCOLS.conf`.
3. Start the script.
4. Point the IR remote at the receiver.
5. Use Raw or Automatic mode to capture and identify the protocol.

[Main Page](../../README.md)