const display = require("display");

// Constructor function instead of class
function TextDisplay() {
    this.lines = [];
    this.maxLines = Math.floor(display.height() / 10);
    this.textColor = display.color(255, 255, 255);
    this.bgColor = display.color(0, 0, 0);
}

TextDisplay.prototype.addLine = function(text) {
    this.lines.push(text);
    if (this.lines.length > this.maxLines) {
        this.lines.shift(); // Remove oldest line
    }
};

TextDisplay.prototype.clear = function() {
    this.lines = [];
};

TextDisplay.prototype.render = function() {
    display.fill(this.bgColor);
    display.setTextColor(this.textColor);
    display.setTextSize(1);
    display.setTextAlign("left", "top");

    for (var i = 0; i < this.lines.length; i++) {
        display.drawString(this.lines[i], 2, i * 10 + 2);
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

for (var i = 0; i < 20; i++) {
    printMessage("Hello, World! " + i);
}

while (true) {    
    if (keyboard.getEscPress(100)) {
        break;
    }
}