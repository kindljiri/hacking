// SubGHz Morse Beacon transmitter.
// Converts A-Z, digits 0-9, and spaces to Morse, then sends raw OOK timing pulses.
// Startup prompts accept frequency in MHz, dot time in milliseconds, and resend delay in seconds.
// Config defaults: 449.81 MHz, 120 ms dot, 10 s resend delay, message "test", and 0 MHz correction.
// JSON settings are loaded from SD:/jsApps/config/SubGHzMorseBeacon.conf.
// Config keys: frequencyMHz, frequencyCorrectionMHz, dotTimeMs, resendDelaySeconds, and message.
// frequencyCorrectionMHz is config-only and is added to the prompted frequency.
// Prompted values override defaults for this run; they are not saved to an existing config file.
// A missing config file is created with defaults; an existing config file is not overwritten.
// Tested with a LilyGo T-Embed + CC1101 running Bruce 1.16.1.

var subghz = require("subghz");
var dialog = require("dialog");
var keyboard = require("keyboard");
var display = require("display");
var storage = require("storage");

var configPath = {
    fs: "sd",
    path: "/jsApps/config/SubGHzMorseBeacon.conf"
};
var config = {
    frequencyMHz: 449.81,
    frequencyCorrectionMHz: 0,
    dotTimeMs: 120,
    resendDelaySeconds: 10,
    message: "test"
};
var configExists = false;

function getInputValue(rawInput, defaultValue) {
    if (rawInput === null || rawInput === undefined) return defaultValue;
    const inputText = "" + rawInput;
    const colonIndex = inputText.lastIndexOf(":");
    const inputValue = (colonIndex >= 0 ? inputText.substring(colonIndex + 1) : inputText).trim();
    return inputValue === "" ? defaultValue : inputValue;
}

function loadConfig() {
    try {
        storage.mkdir({ fs: "sd", path: "/jsApps" });
        storage.mkdir({ fs: "sd", path: "/jsApps/config" });
    } catch (directoryError) {
        console.log("Could not access SD config directory; using defaults.");
        return;
    }

    var configText;
    try {
        configText = storage.read(configPath);
        if (configText === null || configText === undefined || configText === false) return;
        configExists = true;
        if (("" + configText).trim() === "") return;

        const savedConfig = JSON.parse(configText);
        if (typeof savedConfig.frequencyMHz === "number" &&
            savedConfig.frequencyMHz >= 300 && savedConfig.frequencyMHz <= 1000) {
            config.frequencyMHz = savedConfig.frequencyMHz;
        }
        if (typeof savedConfig.frequencyCorrectionMHz === "number") {
            config.frequencyCorrectionMHz = savedConfig.frequencyCorrectionMHz;
        }
        if (typeof savedConfig.dotTimeMs === "number" && savedConfig.dotTimeMs > 0) {
            config.dotTimeMs = savedConfig.dotTimeMs;
        }
        if (typeof savedConfig.resendDelaySeconds === "number" && savedConfig.resendDelaySeconds > 0) {
            config.resendDelaySeconds = savedConfig.resendDelaySeconds;
        }
        if (typeof savedConfig.message === "string") config.message = savedConfig.message;
        console.log("Loaded config from SD: " + configPath.path);
    } catch (configReadError) {
        console.log("Config exists but could not be loaded; using built-in defaults.");
    }
}

function saveConfig() {
    try {
        return storage.write(configPath, JSON.stringify(config, null, 2), "w");
    } catch (configWriteError) {
        console.log("Could not save config to SD card.");
        return false;
    }
}

function generateMorsePattern(message, dotTimeMs) {
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

const version = "v1.1.2";

console.log("SubGHz Morse Beacon " + version);

loadConfig();
if (!configExists && !saveConfig()) {
    console.log("Could not create config file on SD card.");
}

// 1. Get the raw input string from the keyboard
const rawInput = keyboard.numKeyboard(
    "Frequency (Def: " + config.frequencyMHz + " MHz):", "" + config.frequencyMHz
);
var logMsg = "Frequency input by user: " + rawInput;
console.log(logMsg);
// 2. Check if the user cancelled or left it blank
if (rawInput === null || rawInput === undefined) {
    dialog.error("Input cancelled.", true);
    exit();
}

// 3. Parse and validate the number safely
const freqMHz = parseFloat(getInputValue(rawInput, "" + config.frequencyMHz));

if (isNaN(freqMHz) || freqMHz < 300 || freqMHz > 1000) {
    var errMsg = "Invalid frequency." + freqMHz + " MHz not in range (300-1000 MHz)";
    console.log(errMsg);
    dialog.error(errMsg ,true);
    exit();
}

// One T-Embed measured about +0.054 MHz offset; this may be unit-specific.
// Set frequencyCorrectionMHz in the config file; use a negative value if TX is high.
const freqMHzCorrection = config.frequencyCorrectionMHz;
const txFreqMHz = freqMHz + freqMHzCorrection;
if (isNaN(freqMHzCorrection) || txFreqMHz < 300 || txFreqMHz > 1000) {
    const correctionError = "Invalid corrected frequency: " + txFreqMHz + " MHz";
    console.log(correctionError);
    dialog.error(correctionError, true);
    exit();
}
console.log("Frequency correction from config: " + freqMHzCorrection + " MHz");
console.log("Actual TX frequency: " + txFreqMHz + " MHz");

const messageInput = keyboard.keyboard(
    "Morse beacon message (Def: " + config.message + "):", config.message
);
if (messageInput === null || messageInput === undefined) {
    dialog.error("Message input cancelled.", true);
    exit();
}
const message = getInputValue(messageInput, config.message);

const dotTimeInput = keyboard.numKeyboard(
    "Dot time (ms, Def: " + config.dotTimeMs + "):", "" + config.dotTimeMs
);
if (dotTimeInput === null || dotTimeInput === undefined) {
    dialog.error("Dot time input cancelled.", true);
    exit();
}
const dotTimeMs = parseFloat(getInputValue(dotTimeInput, "" + config.dotTimeMs));
if (isNaN(dotTimeMs) || dotTimeMs <= 0) {
    dialog.error("Invalid dot time. Enter a value greater than 0 ms.", true);
    exit();
}

const resendDelayInput = keyboard.numKeyboard(
    "Resend delay (seconds, Def: " + config.resendDelaySeconds + "):", "" + config.resendDelaySeconds
);
if (resendDelayInput === null || resendDelayInput === undefined) {
    dialog.error("Resend delay input cancelled.", true);
    exit();
}
const resendDelaySeconds = parseFloat(getInputValue(resendDelayInput, "" + config.resendDelaySeconds));
const timeout = resendDelaySeconds * 1000;
if (isNaN(resendDelaySeconds) || !isFinite(timeout) || timeout <= 0) {
    dialog.error("Invalid resend delay. Enter a value greater than 0 seconds.", true);
    exit();
}

const rawData = generateMorsePattern(message, dotTimeMs);
if (rawData && rawData.length > 0) {
    console.log("Generated Morse:");
    console.log("RAW_Data: " + rawData.join(" ").substring(0, 100) + "...");

    if (typeof subghz.txSetup !== "function" ||
        typeof subghz.txPulses !== "function" ||
        typeof subghz.txEnd !== "function") {
        dialog.error("Raw pulse TX API unavailable. Update Bruce firmware.");
        exit();
    }

    if (rawData.length > 2048) {
        dialog.error("Morse message is too long to transmit.");
    } else {
        display.fill(display.color(0, 0, 0));
        display.setTextColor(display.color(255, 255, 255));
        display.setTextSize(1);
        display.setTextAlign("center", "middle");
        display.drawString("Press Esc to stop transmitting.", display.width() / 2, display.height() / 2);

        var keepTransmitting = true;
        while (keepTransmitting) {
            if (!subghz.txSetup(txFreqMHz)) {
                console.log("RF initialization failed");
                break;
            }

            const transmitted = subghz.txPulses(rawData);
            subghz.txEnd();
            if (transmitted) {
                console.log("Morse transmitted");
            } else {
                console.log("Raw pulse transmission failed");
            }
            
            console.log("Waiting " + resendDelaySeconds + " seconds before next transmission...");

            for (var waitedMs = 0; waitedMs < timeout; waitedMs += 100) {
                //if (waitedMs % 1000 === 0) {
                //    console.log("Waiting " + Math.ceil((timeout - waitedMs) / 1000) + " seconds before next transmission...");
                //}
                if (keyboard.getEscPress()) {
                    keepTransmitting = false;
                    break;
                }
                delay(100);
            }
        }
    }
}
