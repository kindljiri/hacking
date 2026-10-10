var subghz = require("subghz");
var dialog = require("dialog");
var keyboard = require("keyboard");
var display = require("display");

function generateMorsePattern() {
    const message = keyboard.keyboard("Morse message:", "HELLO");
    const dotTime = parseInt(keyboard.numKeyboard("Dot time (μs):", "500"));
    const dashTime = dotTime * 3;
    const gapTime = dotTime;

    const morseMap = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', ' ': '/'
    };

    const pattern = [];

    for (var char of message.toUpperCase()) {
        const morse = morseMap[char];
        if (!morse) continue;

        if (morse === '/') {
            pattern.push(-dashTime * 2); // Word gap
        } else {
            for (var symbol of morse) {
                if (symbol === '.') {
                    pattern.push(dotTime, -gapTime);
                } else if (symbol === '-') {
                    pattern.push(dashTime, -gapTime);
                }
            }
            pattern.push(-dashTime); // Letter gap
        }
    }

    return "RAW_Data: " + pattern.join(" ");
}

// === MAIN =============


// 1. Get the raw input string from the keyboard
const rawInput = keyboard.numKeyboard("Frequency (Hz):", "433920000");
var logMsg = "Frequency input by user: " + rawInput;
console.log(logMsg);
// 2. Check if the user cancelled or left it blank
if (rawInput === null || rawInput === undefined || rawInput === "") {
    dialog.error("Input cancelled.", true);
    exit();
}

// 3. Parse and validate the number safely
const freq = parseInt(rawInput, 10);

if (isNaN(freq) || freq < 300000000 || freq > 1000000000) {
    var errMsg = "Invalid frequency." + freq + " not in range (300-1000 MHz)";
    dialog.error(errMsg ,true);
    exit();
}

const rawData = generateMorsePattern();
if (rawData) {
    console.log("Generated Morse:");
    console.log(rawData.substring(0, 100) + "...");

    if (subghz.transmit(freq, rawData)) {
        dialog.success("Morse transmitted");
    } else {
        dialog.error("Transmission failed");
    }
}
