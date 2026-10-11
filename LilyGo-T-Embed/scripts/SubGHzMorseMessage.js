// SubGHz Morse Message transmitter.
// Converts entered letters and digits to Morse, then transmits the timing pattern
// as raw OOK pulses at the selected frequency. Dot timing is entered in milliseconds.
// Tested with a LilyGo T-Embed + CC1101 running Bruce 1.16.1.

var subghz = require("subghz");
var dialog = require("dialog");
var keyboard = require("keyboard");
var display = require("display");

function getInputValue(rawInput, defaultValue) {
    if (rawInput === null || rawInput === undefined) return defaultValue;
    const inputText = "" + rawInput;
    const colonIndex = inputText.lastIndexOf(":");
    const inputValue = (colonIndex >= 0 ? inputText.substring(colonIndex + 1) : inputText).trim();
    return inputValue === "" ? defaultValue : inputValue;
}

function generateMorsePattern() {
    const message = getInputValue(keyboard.keyboard("Morse message (Def: test):", "test"), "test");
    const dotTimeMs = parseFloat(getInputValue(
        keyboard.numKeyboard("Dot time (Def: 120 ms):", "120"), "120"
    ));
    if (isNaN(dotTimeMs) || dotTimeMs <= 0) {
        dialog.error("Invalid dot time. Enter a value greater than 0 ms.");
        return null;
    }
    const dotTime = Math.round(dotTimeMs * 1000);
    const dashTime = dotTime * 3;
    const gapTime = dotTime;
    console.log("Morse message: " + message);
    console.log("Dot time: " + dotTimeMs + " ms, Dash time: " + (dotTimeMs * 3) + " ms, Gap time: " + dotTimeMs + " ms");

    const morseMap = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..',
        '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
        '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        ' ': '/'
    };

    const pattern = [];
    const morseCode = [];
    const uppercaseMessage = message.toUpperCase();

    for (var messageIndex = 0; messageIndex < uppercaseMessage.length; messageIndex++) {
        const char = uppercaseMessage[messageIndex];
        const morse = morseMap[char];
        if (!morse) continue;
        morseCode.push(morse);

        if (morse === '/') {
            pattern.push(-dashTime * 2); // Word gap
        } else {
            for (var symbolIndex = 0; symbolIndex < morse.length; symbolIndex++) {
                const symbol = morse[symbolIndex];
                if (symbol === '.') {
                    pattern.push(dotTime, -gapTime);
                } else if (symbol === '-') {
                    pattern.push(dashTime, -gapTime);
                }
            }
            pattern.push(-dashTime); // Letter gap
        }
    }

    console.log("Morse code: " + morseCode.join(" "));
    return pattern;
}

// === MAIN =============

const version = "v1.1.0";
var freqMHzCorrection = 0.0; // Adjust this if your device transmits high or low

console.log("SubGHz Morse Message " + version);

// One T-Embed measured about +0.054 MHz offset; this may be unit-specific.
// Measure your device's carrier; use a negative correction if it transmits high.
// 1. Get the raw input string from the keyboard
const rawInput = keyboard.numKeyboard("Frequency (Def: 449.81 MHz):", "449.81");
var logMsg = "Frequency input by user: " + rawInput;
console.log(logMsg);
// 2. Check if the user cancelled or left it blank
if (rawInput === null || rawInput === undefined) {
    dialog.error("Input cancelled.", true);
    exit();
}

// 3. Parse and validate the number safely
const freqMHz = parseFloat(getInputValue(rawInput, "449.81"));

if (isNaN(freqMHz) || freqMHz < 300 || freqMHz > 1000) {
    var errMsg = "Invalid frequency." + freqMHz + " MHz not in range (300-1000 MHz)";
    console.log(errMsg);
    dialog.error(errMsg ,true);
    exit();
}



const rawData = generateMorsePattern();
if (rawData && rawData.length > 0) {
    console.log("Generated Morse:");
    console.log("RAW_Data: " + rawData.join(" ").substring(0, 100) + "...");

    if (typeof subghz.txSetup !== "function" ||
        typeof subghz.txPulses !== "function" ||
        typeof subghz.txEnd !== "function") {
        dialog.error("Raw pulse TX API unavailable. Update Bruce firmware.");
        exit();
    }

    var txFreqMHz = freqMHz + freqMHzCorrection;

    if (rawData.length > 2048) {
        dialog.error("Morse message is too long to transmit.");
    } else if (subghz.txSetup(txFreqMHz)) {
        const transmitted = subghz.txPulses(rawData);
        subghz.txEnd();
        if (transmitted) {
            dialog.success("Morse transmitted");
        } else {
            dialog.error("Raw pulse transmission failed");
        }
    } else {
        dialog.error("RF initialization failed");
    }
}
