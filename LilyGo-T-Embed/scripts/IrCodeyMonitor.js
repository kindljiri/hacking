const ir = require("ir");
const display = require("display");
const keyboard = require("keyboard");

const black = display.color(0, 0, 0);

// Decodes Codey Rocky raw microsecond timings back into an ASCII string
function decodeCodeyRockyIR(raw) {
    if (!raw || raw.length < 20) return null;

    var bits = [];
    
    // Skip index 0 and 1 (header mark/space) and inspect space intervals (odd indices)
    for (var i = 3; i < raw.length; i += 2) {
        var spaceDuration = raw[i];

        // Threshold tuning: space > 1000us represents bit 1; short space represents bit 0
        if (spaceDuration > 1000) {
            bits.push(1);
        } else if (spaceDuration > 200) {
            bits.push(0);
        }
    }

    // Convert bit stream into 8-bit ASCII characters
    var decodedStr = "";
    for (var b = 0; b < bits.length - 7; b += 8) {
        var byteVal = 0;
        for (var bitIndex = 0; bitIndex < 8; bitIndex++) {
            // Reconstruct byte (assumes LSB first)
            if (bits[b + bitIndex] === 1) {
                byteVal |= (1 << bitIndex);
            }
        }
        
        // Filter readable ASCII printable range (32 to 126) + newline (10)
        if ((byteVal >= 32 && byteVal <= 126) || byteVal === 10) {
            decodedStr += String.fromCharCode(byteVal);
        }
    }

    return decodedStr;
}

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

function logMessage(message) {
    textDisplay.addLine("[" + Date.now() + "] " + message);
    textDisplay.render();
}

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

//keyboard.setLongPress(true); 
printMessage("IR Monitor Started. Press ESC to exit.");

while (true) {
    
    if (keyboard.getEscPress(100)) {
        printMessage("Exiting IR Monitor...");
        break;
    }

    var signal = ir.readRaw(2000);

    if (signal) {
        storage.write("/logs/IrCodeyMonitor.txt", "Received Signal:\n", "a");

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
        storage.write("/logs/IrCodeyMonitor.txt", "Raw Signals: " + rawDataLine + "\n", "a");

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
                storage.write("/logs/IrCodeyMonitor.txt", "Raw Packet: " + rawNECPacket.join(" ") + "\n", "a");
                storage.write("/logs/IrCodeyMonitor.txt", "Extracted Bits: " + bits + "\n", "a");
                storage.write("/logs/IrCodeyMonitor.txt", "Hex Bytes: " + hexBytes + "\n", "a");
                rawNECPacket = [];
            }
        }

        

        printMessage("Received Signal:");
        //printMessage(decodeCodeyRockyIR(signal));
        //console.log("Received IR signal:", signal);
    }
}