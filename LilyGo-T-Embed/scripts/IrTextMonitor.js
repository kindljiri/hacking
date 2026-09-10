const ir = require("ir");
const display = require("display");
const keyboard = require("keyboard");

const black = display.color(0, 0, 0);

// Constructor function instead of class
function TextDisplay() {
    this.lines = [];
    this.charWidth = 6; // approximate width of size-1 font in pixels
    this.lineHeight = 10;
    this.maxCharsPerLine = Math.floor((display.width() - 4) / this.charWidth);
    this.maxLines = Math.floor(display.height() / this.lineHeight);
    this.textColor = display.color(255, 255, 255);
    this.bgColor = display.color(0, 0, 0);
}

TextDisplay.prototype.addLine = function(text) {
    var str = String(text);

    // Break long text into chunks that fit maxCharsPerLine
    while (str.length > this.maxCharsPerLine) {
        this.pushLine(str.substring(0, this.maxCharsPerLine));
        str = str.substring(this.maxCharsPerLine);
    }
    
    if (str.length > 0) {
        this.pushLine(str);
    }
};

TextDisplay.prototype.pushLine = function(line) {
    this.lines.push(line);
    if (this.lines.length > this.maxLines) {
        this.lines.shift(); // Scroll up by removing the top line
    }
};

TextDisplay.prototype.clear = function() {
    this.lines = [];
    display.fill(this.bgColor);
};

TextDisplay.prototype.render = function() {
    display.fill(this.bgColor);
    display.setTextColor(this.textColor);
    display.setTextSize(1);
    display.setTextAlign("left", "top");

    for (var i = 0; i < this.lines.length; i++) {
        display.drawString(this.lines[i], 2, i * this.lineHeight + 2);
    }
};

// Usage
var textDisplay = new TextDisplay();

function logMessage(message) {
    textDisplay.addLine("[" + Date.now() + "] " + message);
    textDisplay.render();
}

function printMessage(message) {
    textDisplay.addLine(message);
    textDisplay.render();
}

printMessage("IR Monitor Started. Press ESC to exit.");

while (true) {
    const signal = ir.readRaw(5);
    
    if (keyboard.getEscPress(10)) {
        printMessage("Exiting IR Monitor...");
        break;
    }

    if (signal) {
        //display.clear();
        //printMessage("Received Signal:");
        printMessage(signal);
        //console.log("Received IR signal:", signal);
    }
}