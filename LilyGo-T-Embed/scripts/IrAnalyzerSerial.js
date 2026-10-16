const version = "v1.0"

// name,type,headerMark,headerSpace,bitMark,zeroSpace,oneSpace,eopGap,totalBits
// PULSE_WIDTH rows use these pulse columns for bitSpace, zeroMark, and oneMark.
// MANCHESTER rows use bitMark for the half-bit unit time.
var KNOWN_PROTOCOLS = [
    ["NEC", "PULSE_DISTANCE", 9000, 4500, 560, 560, 1690, 40000, 32],
    ["SAMSUNG", "PULSE_DISTANCE", 4500, 4500, 560, 560, 1690, 40000, 32],
    ["SONY_SIRC", "PULSE_WIDTH", 2400, 600, 600, 600, 1200, 25000, 12],
    ["PANASONIC", "PULSE_DISTANCE", 3500, 1750, 430, 430, 1300, 10000, 48],
    ["PIONEER", "PULSE_DISTANCE", 8400, 4200, 500, 500, 1500, 25000, 32],
    ["RC6_MODE0", "MANCHESTER", 2666, 889, 444, 0, 0, 10000, 20]
];
var configPath = {
    fs: "sd",
    path: "/jsApps/config/KNOWN_PROTOCOLS.conf"
};

function loadKnownProtocols() {
    try {
        var storage = require("storage");
        var contents = storage.read(configPath);
        if (!contents) return;

        var protocols = JSON.parse(contents);
        if (!Array.isArray(protocols) || protocols.length === 0 || protocols.length > 31) {
            console.log("Invalid protocol file; using built-in profiles.");
            return;
        }

        for (var i = 0; i < protocols.length; i++) {
            var proto = protocols[i];
            if (!Array.isArray(proto) || proto.length !== 9 ||
                typeof proto[0] !== "string" ||
                (proto[1] !== "PULSE_DISTANCE" && proto[1] !== "PULSE_WIDTH" && proto[1] !== "MANCHESTER")) {
                console.log("Invalid protocol row; using built-in profiles.");
                return;
            }
            for (var j = 2; j < 9; j++) {
                if (typeof proto[j] !== "number" || !isFinite(proto[j])) {
                    console.log("Invalid protocol timing; using built-in profiles.");
                    return;
                }
            }
        }

        KNOWN_PROTOCOLS = protocols;
        console.log("Loaded protocol profiles from " + configPath.path);
    } catch (error) {
        console.log("Using built-in protocol profiles.");
    }
}

// Helper: Checks if a canonical value exists in histogram within tolerance
// Histogram helpers use [duration, count] pairs.
function findInHg(hg, target, tolerance) {
    if (!tolerance) tolerance = 250;
    for (var i = 0; i < hg.length; i++) {
        var duration = hg[i][0];
        if (Math.abs(duration - target) <= tolerance) {
            return hg[i];
        }
    }
    return null;
}

// Returns sorted 2D array: [[duration, count], [duration, count], ...]
var dataCursor = 0;

function nextTiming(signal, dataEnd) {
    var sign = 1;
    var value = 0;
    var digits = 0;
    var code = 0;

    while (dataCursor < dataEnd) {
        code = signal.charCodeAt(dataCursor);
        if ((code >= 48 && code <= 57) || code === 45) break;
        dataCursor++;
    }
    if (dataCursor >= dataEnd) return null;

    if (signal.charCodeAt(dataCursor) === 45) {
        sign = -1;
        dataCursor++;
    }
    while (dataCursor < dataEnd) {
        code = signal.charCodeAt(dataCursor);
        if (code < 48 || code > 57) break;
        value = value * 10 + code - 48;
        digits++;
        dataCursor++;
    }
    return digits ? sign * value : null;
}

function getHg(signal, dataStart, dataEnd, binSize) {
    if (!binSize) binSize = 100;

    var histoMap = {};
    var bins = [];

    dataCursor = dataStart;
    var val = nextTiming(signal, dataEnd);
    while (val !== null) {
        if (val === 0) {
            val = nextTiming(signal, dataEnd);
            continue;
        }

        // Neutral timing duration
        var absVal = val < 0 ? -val : val;
        var bin = Math.round(absVal / binSize) * binSize;

        if (histoMap[bin] === undefined) {
            histoMap[bin] = 1;
            bins.push(bin);
        } else {
            histoMap[bin] = histoMap[bin] + 1;
        }
        val = nextTiming(signal, dataEnd);
    }

    // Sort bin values ascending (mJS compatible Bubble Sort)
    for (var x = 0; x < bins.length; x++) {
        for (var y = 0; y < bins.length - 1 - x; y++) {
            if (bins[y] > bins[y + 1]) {
                var temp = bins[y];
                bins[y] = bins[y + 1];
                bins[y + 1] = temp;
            }
        }
    }

    // Construct final 2D array [[binValue, count], ...]
    var hg = [];
    for (var k = 0; k < bins.length; k++) {
        var b = bins[k];
        hg.push([b, histoMap[b]]);
    }

    return hg;
}

// Formats and prints the 2D array histogram
function printHg(hg, title) {
    if (!title) title = "TIMING DISTRIBUTION";
    
    serial.println("\n=== " + title + " ===");

    for (var i = 0; i < hg.length; i++) {
        var duration = hg[i][0];
        var count = hg[i][1];

        // Draw ASCII bar
        var bar = "";
        for (var b = 0; b < count; b++) {
            bar += "#";
        }

        serial.println(duration + " µs [" + count + "]: " + bar);
    }
}

function protoClassify(hg, signal, dataStart, dataEnd, tolerance) {
    if (!tolerance) tolerance = 250;

    var candidates = 0;
    var matchedIndex = -1;
    var matchedOffset = 7;
    var rawHeader = [];
    dataCursor = dataStart;
    for (var h = 0; h < 6; h++) {
        var timing = nextTiming(signal, dataEnd);
        if (timing === null) break;
        rawHeader.push(timing);
    }
    var searchLimit = Math.min(rawHeader.length - 1, 6);

    for (var p = 0; p < KNOWN_PROTOCOLS.length; p++) {
        var proto = KNOWN_PROTOCOLS[p];
        var headerMatch = false;
        var payloadMatch = false;

        if (proto[2] > 0 && proto[3] > 0 &&
            findInHg(hg, proto[2], tolerance) &&
            findInHg(hg, proto[3], tolerance)) {
            headerMatch = true;
        }

        if (proto[1] === "PULSE_DISTANCE") {
            if (findInHg(hg, proto[4], tolerance) &&
                (findInHg(hg, proto[5], tolerance) || findInHg(hg, proto[6], tolerance))) {
                payloadMatch = true;
            }
        } else if (proto[1] === "PULSE_WIDTH") {
            if (findInHg(hg, proto[4], tolerance) &&
                (findInHg(hg, proto[5], tolerance) || findInHg(hg, proto[6], tolerance))) {
                payloadMatch = true;
            }
        } else if (proto[1] === "MANCHESTER") {
            if (findInHg(hg, proto[4], tolerance)) payloadMatch = true;
        }

        if (!headerMatch || !payloadMatch) continue;
        candidates |= 1 << p;

        for (var i = 0; i < searchLimit; i += 2) {
            if (Math.abs(Math.abs(rawHeader[i]) - proto[2]) <= tolerance &&
                Math.abs(Math.abs(rawHeader[i + 1]) - proto[3]) <= tolerance &&
                i < matchedOffset) {
                matchedIndex = p;
                matchedOffset = i;
                break;
            }
        }
    }

    if (matchedIndex >= 0) return matchedIndex;

    if (candidates === 0) {
        serial.println("\n----------------------------------------");
        serial.println("PROTOCOL IDENTIFICATION: UNKNOWN PROTOCOL");
        serial.println("No known protocol matched the timing histogram.");
        serial.println("----------------------------------------");
        return -1;
    }

    var candidateCount = 0;
    var onlyCandidate = -1;
    for (var c = 0; c < KNOWN_PROTOCOLS.length; c++) {
        if (candidates & (1 << c)) {
            candidateCount++;
            onlyCandidate = c;
        }
    }

    serial.println("\n----------------------------------------");
    serial.println("PROTOCOL IDENTIFICATION RESULT");
    serial.println("----------------------------------------");
    if (candidateCount === 1) {
        serial.println("Single Histogram Match: " + KNOWN_PROTOCOLS[onlyCandidate][0]);
    } else {
        serial.println("Candidate Protocols from Histogram:");
        for (var c = 0; c < KNOWN_PROTOCOLS.length; c++) {
            if (candidates & (1 << c)) serial.println("  - " + KNOWN_PROTOCOLS[c][0]);
        }
    }
    serial.println("Header Verification : FAILED (Header sequence not found at stream start)");
    serial.println("----------------------------------------\n");
    return -1;
}

function AnalyzeData(signal, binSize) {
    var dataStart = signal.indexOf("data:");
    if (dataStart < 0) {
        serial.println("Error: No raw 'data:' line found in signal.");
        return;
    }

    dataStart += 5;
    var dataEnd = signal.indexOf("\n", dataStart);
    if (dataEnd < 0) dataEnd = signal.length;

    // 2. Compute and print histogram
    // hg is the duration/count histogram used for protocol matching.
    var hg = getHg(signal, dataStart, dataEnd, binSize);
    printHg(hg, "TIMING DISTRIBUTION");

    // 3. Classify timings and verify the raw header
    var protocolIndex = protoClassify(hg, signal, dataStart, dataEnd, 250);
    if (protocolIndex < 0) return;

    // 5. Output Results
    serial.println("\n----------------------------------------");
    serial.println("PROTOCOL IDENTIFICATION RESULT");
    serial.println("----------------------------------------");

    if (protocolIndex >= 0) {
        var proto = KNOWN_PROTOCOLS[protocolIndex];
        serial.println("Matched Protocol : " + proto[0]);
        serial.println("Header Verification : CONFIRMED");
        serial.println("Canonical Header   : Mark " + proto[2] + " us, Space " + proto[3] + " us");
        serial.println("Encoding Scheme    : " + proto[1]);
        serial.println("Expected Bit Count : " + proto[8]);
    }
    serial.println("----------------------------------------\n");
}

function IrAuto() {
    var ir = require("ir");
    var IrAutoState = "";
    while (IrAutoState != "Exit") {
        console.log("Waiting for signal...");
        var signal = ir.read(timeout); 
        if (signal) {
            console.log("IR signal captured!");
            console.log(signal);
        }
        else {
            console.log("No signal detected.");
        }

        var retryCapture = false;
        while (!retryCapture && IrAutoState != "Exit") {
            serial.println("Pick an option");
            serial.println("--------------");
            serial.println("1) Retry");
            serial.println("2) IR Analyzer Menu");
            serial.println("3) Exit");

            var choice = "";
            while (choice == "") {
                choice = serial.readln(500); // 5 second timeout
            }

            switch (parseInt(choice, 10)) {
                case 1:
                    retryCapture = true;
                    break;
                case 2:
                    IrAutoState = "Exit";
                    break;
                case 3:
                    console.log("Exiting...");
                    IrAutoState = "Exit";
                    globalThis.state = "Exit";
                    break;
                default:
                    break;
            }
        }
    }
}

function IrRaw() {
    var ir = require("ir");
    var IrRawState = "";
    while (IrRawState != "Exit") {
        console.log("Waiting for signal...");
        var signal = ir.readRaw(timeout); 
        if (signal) {
            console.log("IR signal captured!");
            console.log(signal);
        }
        else {
            console.log("No signal detected.");
        }

        var retryCapture = false;
        while (!retryCapture && IrRawState != "Exit") {
            serial.println("Pick an option");
            serial.println("--------------");
            serial.println("1) Retry");
            serial.println("2) IR Analyzer Menu");
            serial.println("3) Analyze data");
            serial.println("4) Exit");

            var choice = "";
            while (choice == "") {
                choice = serial.readln(500); // 5 second timeout
            }

            switch (parseInt(choice, 10)) {
                case 1:
                    retryCapture = true;
                    break;
                case 2:
                    IrRawState = "Exit";
                    break;
                case 3:
                    AnalyzeData(signal);
                    break;
                case 4:
                    console.log("Exiting...");
                    IrRawState = "Exit";
                    globalThis.state = "Exit";
                    break;
                default:
                    break;
            }
        }
    }
}

function SettingsMenu() {
    var SettingsMenuState = "";
    while (SettingsMenuState != "Exit") {
        serial.println("Settings");
        serial.println("--------");
        serial.println("1) Timeout");
        serial.println("2) IR Analyzer Menu");
        serial.println("3) Exit");

        var choice = "";
        while (choice == "") {
            choice = serial.readln(500);
        }

        switch (parseInt(choice, 10)) {
            case 1:
                setTimeout();
                break;
            case 2:
                console.log("Back to IR Analyzer Menu");
                SettingsMenuState = "Exit";
                break;
            case 3:
                globalThis.state = "Exit";
                SettingsMenuState = "Exit";
                break;
            default:
                break;
        }
    }
}

function setTimeout() {
    serial.println("Current timeout:" + globalThis.timeout);
    serial.println("Enter new vaule:");
    while (true) {
        var newVal = serial.readln(500); // 5 second timeout
        if ( newVal != '' ) {
            globalThis.timeout = newVal;
            break;
        }
    }
}

function DrawMainMenu() {
    globalThis.state="Main Menu";
    while (globalThis.state != "Exit") {
        serial.println("IR Analyzer Menu");
        serial.println("----------------");
        serial.println("1) Raw");
        serial.println("2) Automatic");
        serial.println("3) Settings");
        serial.println("4) Exit");

        while (true) {
            const choice = serial.readln(500);
            if ( choice != '' ) {
                break;
            }
        }

        console.log(choice);

        switch (parseInt(choice, 10)) {
            case 1:
                console.log("Raw");
                IrRaw();
                break;
            case 2:
                console.log("Automatic");
                IrAuto();
                break;
            case 3:
                console.log("Settings");
                SettingsMenu();
                break;
            case 4:
                console.log("Exiting...");
                globalThis.state = "Exit";
                break;
            default:
                break;
        }
        choice='';
    }
}

console.log("Infrared Analyzer " + version);
var timeout = 200;
var state = "Main Menu";

function showStartupMessage() {
    var display = require("display");
    var textColor = display.color(255, 255, 255);
    display.fill(display.color(0, 0, 0));
    display.setTextColor(textColor);
    display.setTextAlign("center", "middle");
    display.setTextSize(2);
    display.drawString("IR Analyzer", display.width() / 2, display.height() / 2 - 12);
    display.setTextSize(1);
    display.drawString("Use Serial Monitor", display.width() / 2, display.height() / 2 + 10);
}

showStartupMessage();
loadKnownProtocols();
DrawMainMenu();