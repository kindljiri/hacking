const audio = require("audio");
const display = require("display");

// Base timing unit in milliseconds
const UNIT = 100; // adjust as needed
const FREQUENCY = 600;

// Play a single Morse symbol (dot or dash)
function playSymbol(symbol, frequency) {
  if (symbol === ".") {
    audio.tone(frequency, 1 * UNIT);
  } else if (symbol === "-") {
    audio.tone(frequency, 3 * UNIT);    
  }
  //DEBUG:
  display.print(symbol);
}

// Main function: play a Morse string like ".- -... / -.-."
function playMorse(morseString) {
  const words = morseString.trim().split(" / ");

  for (var w = 0; w < words.length; w++) {
    const letters = words[w].split(" ");

    for (var l = 0; l < letters.length; l++) {
      const symbols = letters[l].split("");

      // Play each symbol in the letter
      for (var s = 0; s < symbols.length; s++) {
        playSymbol(symbols[s], FREQUENCY);
        delay(1 * UNIT); // gap after symbol
      }

      // After each letter, add letter gap (3 units)
      // But we already added 1 unit after the last symbol,
      // so add only 2 more units.
      if (l < letters.length - 1) {
        delay(2 * UNIT);
        display.print(" ")
      }

    }

    // After each word, add word gap (7 units)
    // We already added 1 unit after last symbol and 2 units after letter,
    // so add 4 more units.
    if (w < words.length - 1) {
      delay(4 * UNIT);
      display.print("/")
    }
  }
}

display.println("Playing morse code:");
display.println("... --- ...");
playMorse("... --- ...");