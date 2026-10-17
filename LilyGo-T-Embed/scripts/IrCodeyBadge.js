// IrCodeyBadge.js
// This app sends a text message to a Codey badge over IR.
// It prompts for a short text string, then transmits one NEC code per character.
// The Codey side expects a message ending in \n, and each ASCII byte is encoded
// as a NEC-style IR value with address 0x00FF and command = ASCII code.

var ir = require("ir");
var dialog = require("dialog");

function encodeCodeyChar(ch) {
    var ascii = ch.charCodeAt(0);
    var address = 0x00FF;
    var command = ascii & 0xFF;
    var invCommand = (~command) & 0xFF;

    // Standard NEC frame layout:
    // [address 16 bits][command 8 bits][inverse command 8 bits]
    // Example: 'A' = 0x41 -> 0x00FF41BE
    return ((address << 16) | (command << 8) | invCommand) >>> 0;
}

function sendTextToBadge(text) {
    if (text === null || text === undefined) return;

    var payload = String(text).trim();
    if (payload.length === 0) return;

    payload += "\n";

    for (var i = 0; i < payload.length; i++) {
        var ch = payload.charAt(i);
        var data = encodeCodeyChar(ch);
        var packet = ("00000000" + data.toString(16).toUpperCase()).slice(-8);

        console.log("Sending: '" + ch + "' => 0x" + packet);
        ir.transmit(packet, "NEC", 32);
    }
}

const version = "v1.0";
console.log("IrCodeyBadge " + version + " - Send text to Codey badge over IR");

var input = dialog.prompt("g33k", 32, "CodeyBadge");
if (input !== null && input !== undefined && input !== "") {
    sendTextToBadge(input);
}
