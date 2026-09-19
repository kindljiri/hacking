var ir = require("ir");
var display = require("display");
var keyboard = require("keyboard");
var dialog = require("dialog");

const version = "v0.9.6"

// Main menu
// - Raw
// - Automatic
// - Settings
//   - Timeout (default 200ms)I

function AnalyzeData(signal, binSize) {
    if (!binSize) binSize = 100; // 100µs resolution binning

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
        serial.println("No raw 'data:' line found.");
        return;
    }

    // 2. Bin absolute durations regardless of mark/space polarity
    var rawTokens = rawDataLine.split(" ");
    var histogram = {};
    var bins = []; // Keep track of unique bins for sorting in mJS

    for (var j = 0; j < rawTokens.length; j++) {
        var token = rawTokens[j].trim();
        if (token === "") continue;

        var val = parseInt(token, 10);
        if (isNaN(val) || val === 0) continue;

        // Take absolute duration (neutral timing)
        var absVal = val < 0 ? -val : val;
        var bin = Math.round(absVal / binSize) * binSize;

        if (histogram[bin] === undefined) {
            histogram[bin] = 1;
            bins.push(bin);
        } else {
            histogram[bin] = histogram[bin] + 1;
        }
    }

    // 3. Simple Bubble Sort for mJS compatibility
    for (var x = 0; x < bins.length; x++) {
        for (var y = 0; y < bins.length - 1 - x; y++) {
            if (bins[y] > bins[y + 1]) {
                var temp = bins[y];
                bins[y] = bins[y + 1];
                bins[y + 1] = temp;
            }
        }
    }

    // 4. Print single visual timing distribution
    serial.println("\n=== TIMING DISTRIBUTION (Combined) ===");
    for (var k = 0; k < bins.length; k++) {
        var binVal = bins[k];
        var count = histogram[binVal];

        var bar = "";
        for (var b = 0; b < count; b++) {
            bar += "#";
        }

        serial.println(binVal + " µs [" + count + "]: " + bar);
    }
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

        serial.println("Pick an option");
        serial.println("--------------");
        serial.println("1) Retry");
        serial.println("2) IR Analyzer Menu");
        serial.println("3) Exit");

        while (true) {
            const choice = serial.readln(5000); // 5 second timeout
            if ( choice != '' ) {
                break;
            }
        }

        switch (parseInt(choice, 10)) {
            case 1:
                continue;
                break;
            case 2:
                IrAutoState = "Exit";
                break;
            case 3:
                console.log("Exiting...");
                globalThis.state = "Exit";
                break;
            default:
                break;
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

        serial.println("Pick an option");
        serial.println("--------------");
        serial.println("1) Retry");
        serial.println("2) IR Analyzer Menu");
        serial.println("3) Analyze data");
        serial.println("4) Exit");

        while (true) {
            const choice = serial.readln(5000); // 5 second timeout
            if ( choice != '' ) {
                break;
            }
        }

        switch (parseInt(choice, 10)) {
            case 1:
                continue;
                break;
            case 2:
                IrRawState = "Exit";
                break;
            case 3:
                AnalyzeData(signal);
                break;
            case 4:
                console.log("Exiting...");
                globalThis.state = "Exit";
                break;
            default:
                break;
        }
    }
}

function SettingsMenu() {
    serial.println("Settings");
    serial.println("--------");
    serial.println("1) Timeout");
    serial.println("2) IR Analyzer Menu");
    serial.println("3) Exit");

    while (true) {
        const choice = serial.readln(5000); // 5 second timeout
        if ( choice != '' ) {
            break;
        }
    }

    switch (parseInt(choice, 10)) {
        case 1:
            setTimeout();
            break;
        case 2:
            console.log("Back to IR Analyzer Menu");
            break;
        case 3:
            globalThis.state = "Exit";
            runtime.exit(0);
            break;
        default:
            break;
    }
}

function setTimeout() {
    serial.println("Current timeout:" + globalThis.timeout);
    serial.println("Enter new vaule:");
    while (true) {
        var newVal = serial.readln(5000); // 5 second timeout
        if ( newVal != '' ) {
            globalThis.timeout = newVal;
            break;
        }
    }
}

function DrawMainMenu() {
    globalThis.state="Main Menu";
    while (state != "Exit") {
        serial.println("IR Analyzer Menu");
        serial.println("----------------");
        serial.println("1) Raw");
        serial.println("2) Automatic");
        serial.println("3) Settings");
        serial.println("4) Exit");

        while (true) {
            const choice = serial.readln(5000); // 5 second timeout
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
    }
}

console.log("Infrared Analyzer" + version);
var timeout = 200;
var state = "Main Menu";

while(true) {
    DrawMainMenu();
}
