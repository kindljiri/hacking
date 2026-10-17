const ir = require("ir");
const display = require("display");
const keyboard = require("keyboard");

// Constructor function instead of class
function TextDisplay() {
    this.lines = [];
    this.charWidth = 6; // approximate width of size-1 font in pixels
    this.lineHeight = 10;
    this.maxCharsPerLine = Math.floor((display.width() - 4) / this.charWidth);
    this.maxLines = Math.floor(display.height() / this.lineHeight);
    this.textColor = display.color(255, 255, 255);
    this.bgColor = display.color(0, 0, 0);
}

TextDisplay.prototype.addLine = function(text) {
    var str = String(text);

    // Break long text into chunks that fit maxCharsPerLine
    while (str.length > this.maxCharsPerLine) {
        this.pushLine(str.substring(0, this.maxCharsPerLine));
        str = str.substring(this.maxCharsPerLine);
    }
    
    if (str.length > 0) {
        this.pushLine(str);
    }
};

TextDisplay.prototype.pushLine = function(line) {
    this.lines.push(line);
    if (this.lines.length > this.maxLines) {
        this.lines.shift(); // Scroll up by removing the top line
    }
};

TextDisplay.prototype.clear = function() {
    this.lines = [];
    display.fill(this.bgColor);
};

TextDisplay.prototype.render = function() {
    display.fill(this.bgColor);
    display.setTextColor(this.textColor);
    display.setTextSize(1);
    display.setTextAlign("left", "top");

    for (var i = 0; i < this.lines.length; i++) {
        display.drawString(this.lines[i], 2, i * this.lineHeight + 2);
    }
};

// Usage
var textDisplay = new TextDisplay();

function printMessage(message) {
    textDisplay.addLine(message);
    textDisplay.render();
}

function rawNECToBits(rawNECTimings) {
    var bits = [];
    // Skip header (indices 0 & 1). Loop through the remaining timings in steps of 2.
    // Index 2, 4, 6... are mark pulses.
    // Index 3, 5, 7... are space durations containing our binary data.
    for (var i = 3; i < rawNECTimings.length; i += 2) {
        var spaceDuration = rawNECTimings[i];

        // Threshold check:
        if (spaceDuration > 1200 && spaceDuration < 2200) {
            bits.push(1); // Long gap = 1
        } else if (spaceDuration > 300 && spaceDuration < 1000) {
            bits.push(0); // Short gap = 0
        } else {
            // If the space is very long (~32,000us), we hit the end of the byte packet
            break; 
        }
    }

    // Step 1: Split the raw bits into groups of 8 (bytes)
    var bytes = [];
    for (var j = 0; j < bits.length; j += 8) {
        var singleByte = bits.slice(j, j + 8);
        bytes.push(singleByte);
    }

    // Step 2: Reverse each individual 8-bit byte array (LSB -> MSB)
    var reversedBytes = [];
    for (var k = 0; k < bytes.length; k++) {
        var reversedByte = bytes[k].slice().reverse();
        reversedBytes.push(reversedByte);
    }

    // Step 3: Join everything back into a single continuous bitstring
    var bitString = "";
    for (var m = 0; m < reversedBytes.length; m++) {
        bitString += reversedBytes[m].join("");
    }

    return bitString;
}

function bitsToHexBytes(bitString) {
    if (!bitString || bitString.length < 32) return "";

    var hexBytes = [];

    // Loop through every 8 bits (4 bytes total)
    for (var i = 0; i < 32; i += 8) {
        var byteChunk = bitString.substring(i, i + 8);
        
        // Convert binary string to integer
        var decimalVal = parseInt(byteChunk, 2);

        // Convert integer to uppercase Hex, padded with leading zero if needed
        var hexVal = decimalVal.toString(16).toUpperCase();
        if (hexVal.length < 2) {
            hexVal = "0" + hexVal;
        }

        hexBytes.push(hexVal);
    }

    // Join the 4 byte strings with spaces
    return hexBytes.join(" ");
}

function decodeHexBytesToText(hexBytes) {
    if (!hexBytes) return { text: "", value: null };

    var bytes = hexBytes.split(/\s+/);
    if (bytes.length < 4) return { text: "", value: null };

    // NEC-style payload layout: [ADDR] [~ADDR] [DATA] [~DATA]
    var payloadHex = bytes[2];
    var payloadValue = parseInt(payloadHex, 16);
    if (isNaN(payloadValue)) return { text: "", value: null };

    // Only accept printable ASCII characters.
    if (payloadValue >= 32 && payloadValue <= 126) {
        return { text: String.fromCharCode(payloadValue), value: payloadValue };
    }

    return { text: "", value: payloadValue };
}

const version = "v1.0.4";
console.log("IrCodeyMonitor " + version + " - Monitor IR signals from Codey Rocky");

//keyboard.setLongPress(true); 
printMessage("IR Codey Receiver " + version + ". Press ESC to exit.");

var logFile = {
    fs: "sd",
    path: "/logs/IrCodeyMonitor.txt"
};

while (true) {
    
    if (keyboard.getEscPress(100)) {
        printMessage("Exiting IR Monitor...");
        break;
    }

    var signal = ir.readRaw(2000);
    var messageString = "";
    if (signal) {
        storage.write(logFile, "Received Signal:\n", "a");

        // As Raw IR data(signal) looks like below:
        // Filetype: IR signals file
        // Version: 1
        // #
        // #
        // name: Unknown
        // type: raw
        // frequency: 38000
        // duty_cycle: 0.33
        // data: 9006 4540 482 596 510 596 536 ...

        // Step 1: Break the multiline string into an array of lines
        var lines = signal.split("\n");
        var rawDataLine = "";

        // Step 2: Loop through every line until we find one starting with "data:"
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            
            if (line.indexOf("data:") === 0) {
                // Step 3: Remove "data:" prefix and keep the rest
                rawDataLine = line.replace("data:", "").trim();
                break; // Stop looking once found
            }
        }
        storage.write(logFile, "Raw Signals: " + rawDataLine + "\n", "a");

        // 1. Split text on spaces
        var tokens = rawDataLine.split(/\s+/); // regex \s+ handles single or multiple spaces

        // 2. Parse into numbers array
        var timings = [];
        for (var i = 0; i < tokens.length; i++) {
            var val = parseInt(tokens[i], 10);
            if (!isNaN(val)) {
                timings.push(val);
            }
        }
        
        var rawNECPacket = []; 
        for (var i = 0; i < timings.length; i++) {
            rawNECPacket.push(timings[i]);
            if (timings[i] > 30000) { 
                var bits = rawNECToBits(rawNECPacket);
                // rawNECToBits returns a bit string, not an array.
                var hexBytes = bitsToHexBytes(bits);
                storage.write(logFile, "Raw Packet: " + rawNECPacket.join(" ") + "\n", "a");
                storage.write(logFile, "Extracted Bits: " + bits + "\n", "a");
                storage.write(logFile, "Hex Bytes: " + hexBytes + "\n", "a");
                console.log("Raw Packet: " + rawNECPacket.join(" "));
                console.log("Extracted Bits: " + bits);
                console.log("Hex Bytes: " + hexBytes);
                rawNECPacket = [];

                var decoded = decodeHexBytesToText(hexBytes);
                if (decoded.text) {
                    messageString += decoded.text;
                    storage.write(logFile, "Decoded ASCII value: " + decoded.value + " (" + decoded.text + ")\n", "a");
                    storage.write(logFile, "Decoded Text from packet: " + decoded.text + "\n", "a");
                } else if (decoded.value !== null) {
                    storage.write(logFile, "Decoded ASCII value: " + decoded.value + " (non-printable)\n", "a");
                }
            }
        }

        printMessage("Received Signal:");
        printMessage(messageString);
        console.log("Received Message:", messageString);
        if (messageString) {
            storage.write(logFile, "Decoded Message: " + messageString + "\n", "a");
        } else {
            storage.write(logFile, "Decoded Message: <empty>\n", "a");
        }
        //console.log("Received IR signal:", signal);
    }
}