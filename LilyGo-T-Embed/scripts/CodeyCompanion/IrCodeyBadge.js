// IrCodeyBadge.js
// This app sends a text message to a Codey badge over IR.
// Characters are separated by Unit Separator (ASCII 31), and the message ends
// with a newline so Codey can distinguish repeated characters and message end.
// NEC command bits are reversed because Codey's decoder reports them in wire order.

var ir = require("ir");
var dialog = require("dialog");

function encodeCodeyChar(ch) {
    var ascii = ch.charCodeAt(0);
    var address = 0x00FF;
    var command = 0;

    // NEC sends each byte least-significant bit first. Reverse the ASCII bits
    // so Codey's decoder reconstructs the original character value.
    for (var bit = 0; bit < 8; bit++) {
        command = (command << 1) | ((ascii >> bit) & 1);
    }

    // NEC command bytes include the bitwise inverse immediately after the command.
    var invCommand = (~command) & 0xFF;

    // Standard NEC frame layout:
    // [address 16 bits][command 8 bits][inverse command 8 bits].
    return ((address << 16) | (command << 8) | invCommand) >>> 0;
}

function transmitCodeyChar(ch) {
    var data = encodeCodeyChar(ch);
    // Keep leading zeroes so ir.transmit receives a full 32-bit NEC frame.
    var packet = ("00000000" + data.toString(16).toUpperCase()).slice(-8);

    console.log("Sending: '" + ch + "' => 0x" + packet);
    ir.transmit(packet, "NEC", 32);
}

function sendTextToBadge(text) {
    // A cancelled prompt has no text to send.
    if (text === null || text === undefined) return;

    // Remove surrounding whitespace before sending; an empty message has no frame.
    var payload = String(text).trim();
    if (payload.length === 0) return;

    for (var i = 0; i < payload.length; i++) {
        transmitCodeyChar(payload.charAt(i));
        if (i < payload.length - 1) {
            // Send ASCII 31 between characters, including identical neighbors,
            // so the receiver can detect boundaries without relying on timing.
            delay(30);
            transmitCodeyChar(String.fromCharCode(0x1F));
            delay(30);
        }
    }
    // Mark the end of the complete message for the Codey-side receiver.
    transmitCodeyChar("\n");
}

const version = "v1.3";
console.log("");
console.log("IrCodeyBadge " + version + " - Send text to Codey badge over IR");

var input = dialog.prompt("g33k", 32, "CodeyBadge");
if (input !== null && input !== undefined && input !== "") {
    sendTextToBadge(input);
}
