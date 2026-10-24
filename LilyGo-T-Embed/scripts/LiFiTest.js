var display = require("display");

// Initialize standard 4-CSK + Delimiter display objects
var COLOR_BLACK  = display.color(0, 0, 0);       // Strobe / Sync Delimiter
var COLOR_RED    = display.color(255, 0, 0);     // 00 -> Index 0
var COLOR_GREEN  = display.color(0, 255, 0);     // 01 -> Index 1
var COLOR_BLUE   = display.color(0, 0, 255);     // 10 -> Index 2
var COLOR_YELLOW = display.color(255, 255, 0);   // 11 -> Index 3

/**
 * Step 1: Converts an ASCII string into an array of hex numbers (0x00 to 0xFF).
 * Example: "OK" -> [0x4F, 0x4B]
 */
function string2hex(str) {
    var hexArray = [];
    for (var i = 0; i < str.length; i++) {
        hexArray.push(str.charCodeAt(i) & 0xFF);
    }
    return hexArray;
}

/**
 * Step 2: Converts a single hex byte (e.g. 0x4F) into an array of 4 display colors.
 * Splits the 8-bit byte into four 2-bit chunks (MSB to LSB).
 */
function hex2colorcode(hexByte) {
    // Array of palette lookup colors matching index 0..3
    var palette = [COLOR_RED, COLOR_GREEN, COLOR_BLUE, COLOR_YELLOW];
    
    // Extract 2-bit pairs from MSB to LSB
    var symbol0 = (hexByte >> 6) & 0x03; // Bits 7..6
    var symbol1 = (hexByte >> 4) & 0x03; // Bits 5..4
    var symbol2 = (hexByte >> 2) & 0x03; // Bits 3..2
    var symbol3 = hexByte & 0x03;        // Bits 1..0

    return [
        palette[symbol0],
        palette[symbol1],
        palette[symbol2],
        palette[symbol3]
    ];
}