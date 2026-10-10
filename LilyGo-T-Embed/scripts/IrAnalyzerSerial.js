var ir = require("ir");
var display = require("display");
var keyboard = require("keyboard");
var dialog = require("dialog");

const version = "v0.9.17";

var KNOWN_PROTOCOLS = [
    {
        name: "NEC",
        type: "PULSE_DISTANCE",
        headerMark: 9000,
        headerSpace: 4500,
        bitMark: 560,       // Fixed mark duration for all bits
        zeroSpace: 560,     // Short space = Bit 0
        oneSpace: 1690,     // Long space = Bit 1
        eopGap: 40000,      // Minimum trailing gap before repeat/frame end
        totalBits: 32
    },
    {
        name: "SAMSUNG",
        type: "PULSE_DISTANCE",
        headerMark: 4500,
        headerSpace: 4500,
        bitMark: 560,
        zeroSpace: 560,
        oneSpace: 1690,
        eopGap: 40000,
        totalBits: 32
    },
    {
        name: "SONY_SIRC",
        type: "PULSE_WIDTH",
        headerMark: 2400,
        headerSpace: 600,
        zeroMark: 600,      // Short mark = Bit 0
        oneMark: 1200,      // Long mark = Bit 1
        bitSpace: 600,      // Fixed space duration between marks
        eopGap: 25000,
        totalBits: 12       // Standard SIRC is 12 bits (or 15, 20)
    },
    {
        name: "PANASONIC",
        type: "PULSE_DISTANCE",
        headerMark: 3500,
        headerSpace: 1750,
        bitMark: 430,
        zeroSpace: 430,
        oneSpace: 1300,
        eopGap: 10000,
        totalBits: 48
    },
    {
        name: "PIONEER",
        type: "PULSE_DISTANCE",
        headerMark: 8400,
        headerSpace: 4200,
        bitMark: 500,
        zeroSpace: 500,
        oneSpace: 1500,
        eopGap: 25000,
        totalBits: 32
    },
    {
        name: "RC6_MODE0",
        type: "MANCHESTER",
        headerMark: 2666,
        headerSpace: 889,
        unitTime: 444,      // Half-bit time slice
        eopGap: 10000,
        totalBits: 20
    }
];

// Helper: Checks if a canonical value exists in histogram within tolerance
function findInHistogram(histogram2D, target, tolerance) {
    if (!tolerance) tolerance = 250;
    for (var i = 0; i < histogram2D.length; i++) {
        var duration = histogram2D[i][0];
        if (Math.abs(duration - target) <= tolerance) {
            return histogram2D[i]; // Returns [duration, count]
        }
    }
    return null;
}

// Helper: Finds largest gap duration in histogram (candidate for EOP)
function findEopInHistogram(histogram2D, minEopThreshold) {
    if (!minEopThreshold) minEopThreshold = 5000;
    var maxGap = 0;
    for (var i = 0; i < histogram2D.length; i++) {
        var duration = histogram2D[i][0];
        if (duration >= minEopThreshold && duration > maxGap) {
            maxGap = duration;
        }
    }
    return maxGap;
}

// Returns sorted 2D array: [[duration, count], [duration, count], ...]
function getHistogram(rawTokens, binSize) {
    if (!binSize) binSize = 100;

    var histoMap = {};
    var bins = [];

    for (var j = 0; j < rawTokens.length; j++) {
        var token = rawTokens[j].trim();
        if (token === "") continue;

        var val = parseInt(token, 10);
        if (isNaN(val) || val === 0) continue;

        // Neutral timing duration
        var absVal = val < 0 ? -val : val;
        var bin = Math.round(absVal / binSize) * binSize;

        if (histoMap[bin] === undefined) {
            histoMap[bin] = 1;
            bins.push(bin);
        } else {
            histoMap[bin] = histoMap[bin] + 1;
        }
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
    var histogram2D = [];
    for (var k = 0; k < bins.length; k++) {
        var b = bins[k];
        histogram2D.push([b, histoMap[b]]);
    }

    return histogram2D;
}

// Formats and prints the 2D array histogram
function printHistogram(histogram2D, title) {
    if (!title) title = "TIMING DISTRIBUTION";
    
    serial.println("\n=== " + title + " ===");

    for (var i = 0; i < histogram2D.length; i++) {
        var duration = histogram2D[i][0];
        var count = histogram2D[i][1];

        // Draw ASCII bar
        var bar = "";
        for (var b = 0; b < count; b++) {
            bar += "#";
        }

        serial.println(duration + " µs [" + count + "]: " + bar);
    }
}

function classifyFromHistogram(histogram2D, tolerance) {
    if (!tolerance) tolerance = 250;
    var matchedCandidates = [];

    for (var p = 0; p < KNOWN_PROTOCOLS.length; p++) {
        var proto = KNOWN_PROTOCOLS[p];
        var headerMatch = false;
        var payloadMatch = false;

        // 1. Check Header components in Histogram
        if (proto.header) {
            var hMark = findInHistogram(histogram2D, proto.header.mark, tolerance);
            var hSpace = findInHistogram(histogram2D, proto.header.space, tolerance);
            if (hMark && hSpace) {
                headerMatch = true;
            }
        }

        // 2. Check Payload timing ratios in Histogram
        if (proto.encoding === "PULSE_DISTANCE") {
            var bMark = findInHistogram(histogram2D, proto.payload.bitMark, tolerance);
            var zSpace = findInHistogram(histogram2D, proto.payload.zeroSpace, tolerance);
            var oSpace = findInHistogram(histogram2D, proto.payload.oneSpace, tolerance);
            if (bMark && (zSpace || oSpace)) {
                payloadMatch = true;
            }
        } else if (proto.encoding === "PULSE_WIDTH") {
            var bSpace = findInHistogram(histogram2D, proto.payload.bitSpace, tolerance);
            var zMark = findInHistogram(histogram2D, proto.payload.zeroMark, tolerance);
            var oMark = findInHistogram(histogram2D, proto.payload.oneMark, tolerance);
            if (bSpace && (zMark || oMark)) {
                payloadMatch = true;
            }
        }

        // 3. Check EOP
        var detectedEop = findEopInHistogram(histogram2D, proto.eopMin);

        if (headerMatch && payloadMatch) {
            matchedCandidates.push({
                protocol: proto,
                eopDetected: detectedEop,
                confidence: "HIGH"
            });
        } else if (headerMatch || payloadMatch) {
            matchedCandidates.push({
                protocol: proto,
                eopDetected: detectedEop,
                confidence: "MEDIUM"
            });
        }
    }

    return matchedCandidates;
}

function verifyHeaderInRaw(rawTokens, candidateProtocols, tolerance) {
    if (!tolerance) tolerance = 250;

    // Search preamble window (first 6 tokens)
    var searchLimit = Math.min(rawTokens.length - 1, 6);

    for (var i = 0; i < searchLimit; i += 2) {
        var rawMark = Math.abs(parseInt(rawTokens[i], 10));
        var rawSpace = Math.abs(parseInt(rawTokens[i + 1], 10));

        for (var c = 0; c < candidateProtocols.length; c++) {
            var proto = candidateProtocols[c].protocol;
            if (!proto.header) continue;

            if (Math.abs(rawMark - proto.header.mark) <= tolerance &&
                Math.abs(rawSpace - proto.header.space) <= tolerance) {

                return {
                    verified: true,
                    protocol: proto,
                    headerMark: proto.header.mark,
                    headerSpace: proto.header.space,
                    markIndex: i,
                    spaceIndex: i + 1,
                    payloadStart: i + 2
                };
            }
        }
    }

    return {
        verified: false,
        protocol: null,
        headerMark: 0,
        headerSpace: 0,
        payloadStart: 0
    };
}

function AnalyzeData(signal, binSize) {
    var lines = signal.split("\n");
    var rawDataLine = "";

    // 1. Locate raw data line
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (line.indexOf("data:") === 0) {
            rawDataLine = line.replace("data:", "").trim();
            break;
        }
    }

    if (!rawDataLine) {
        serial.println("Error: No raw 'data:' line found in signal.");
        return;
    }

    var rawTokens = rawDataLine.split(" ").filter(function(t) { return t.length > 0; });

    // 2. Compute and print histogram
    var histogram = getHistogram(rawTokens, binSize);
    printHistogram(histogram, "TIMING DISTRIBUTION (Combined)");

    // 3. Fast histogram classification
    var candidates = classifyFromHistogram(histogram, 250);

    if (candidates.length === 0) {
        serial.println("\n----------------------------------------");
        serial.println("PROTOCOL IDENTIFICATION: UNKNOWN PROTOCOL");
        serial.println("No known protocol matched the timing histogram.");
        serial.println("----------------------------------------");
        return;
    }

    // 4. Verify header alignment in raw data
    var headerCheck = verifyHeaderInRaw(rawTokens, candidates, 250);

    // 5. Output Results
    serial.println("\n----------------------------------------");
    serial.println("PROTOCOL IDENTIFICATION RESULT");
    serial.println("----------------------------------------");

    if (headerCheck.verified) {
        var proto = headerCheck.protocol;
        serial.println("Matched Protocol : " + proto.name);
        serial.println("Header Verification : CONFIRMED at index " + headerCheck.markIndex);
        serial.println("Canonical Header   : Mark " + proto.header.mark + " us, Space " + proto.header.space + " us");
        serial.println("Encoding Scheme    : " + proto.encoding);
        serial.println("Expected Bit Count : " + proto.expectedBits);

        // Optional: Perform payload parsing since header alignment is confirmed
        var decoded = decodePayloadStream(rawTokens, headerCheck, 250);
        if (decoded && decoded.bitCount > 0) {
            serial.println("Decoded Bitstream  : " + decoded.bitString);
            serial.println("Decoded Hex        : 0x" + decoded.hexValue + " (" + decoded.bitCount + " bits)");
        } else {
            serial.println("Payload Parsing    : Unable to parse valid bits.");
        }
    } else {
        serial.println("Candidate Guess(es) from Histogram:");
        for (var c = 0; c < candidates.length; c++) {
            var cand = candidates[c];
            serial.println("  - " + cand.protocol.name + " (Confidence: " + cand.confidence + ")");
        }
        serial.println("Header Verification : FAILED (Header sequence not found at stream start)");
    }
    serial.println("----------------------------------------\n");
}

function IrAuto() {
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

DrawMainMenu();