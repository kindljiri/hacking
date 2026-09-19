var ir = require("ir");
var display = require("display");
var keyboard = require("keyboard");
var dialog = require("dialog");
const black = display.color(0, 0, 0);

// Main menu
// - Raw
// - Automatic
// - Settings
//   - Timeout (default 200ms)I



function DrawMainMenu() {
    const choice = dialog.choice([
        "Raw",
        "Automatic",
        "Settings",
        "Exit"
    ]);
    
    console.log(choice);

    switch (choice) {
        case 0:
            console.log("Raw");
            IrRaw();
            break;
        case 1:
            console.log("Automatic");
            IrAuto();
            break;
        case 2:
            console.log("Settings");
            SettingsMenu();
            break;
        case 3:
            console.log("Exiting...");
            break;
        default:
            break;
    }
}

function IrAuto() {
    console.log("Waiting for signal...");
    dialog.info("Waiting for signal...", false); // Non-blocking
    var signal = ir.read(timeout); 
    if (signal) {
        console.log("IR signal captured!");
        console.log(signal);
        const viewer = dialog.createTextViewer("IR Signal", signal);

        viewer.draw();

        // Navigate through content
        while (true) {
            if (keyboard.getNextPress(100)) {
                viewer.scrollDown();
                viewer.draw();
            } else if (keyboard.getPrevPress(100)) {
                viewer.scrollUp();
                viewer.draw();
            } else if (keyboard.getEscPress(100)) {
                break;
            }

            delay(50);
        }

        viewer.close();
        
    } else {
        dialog.warning("No signal detected", true);
    }
}

function IrRaw() {
    dialog.warning("Not implemented", true);
}

function SettingsMenu() {
    dialog.warning("Not implemented", true);
}

console.log("Infrared Analyzer");
var timeout = 200

DrawMainMenu();