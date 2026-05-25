# Codey Rocky

Is nice [toy for kids](https://www.makeblock.com/pages/codey-rocky-robot-toys-for-kids) to learn programing. It suppor makeblock programing. 
So cool for kids, right?
Or is it?

Well basically it is ESP32 on wheels just see [specs](HWInfo.md)
And it supports [micropython](https://makeblock-micropython-api.readthedocs.io/en/latest/codey&rocky/)

## G33kOS

Is small "OS" written in python and currently in alpha
[G33kOS](Codey.py)

Functions assigned to buttons:
A) Infrared Remote controled Menu
B) NEC Ir Decoder - display the NEC Codes in format of Address:Command
C) No function yet

### Infrared Remote controled Menu
Offer functionalities controled by Infrared remote. I use this [Emos](EmosIr.md)
You will need to find your Address and Commands, and update code accordingly to use your remote.
I use the Arrows, OK, Exit for basic navigation.
Main Menu:
- IRDrive
- Batter
- Dice

#### IRDrive
Let you drive the Codey Rocky with Ir Remote Control. 
I use this [Emos](EmosIr.md)

|Button|Function|
|------|--------|
|Up Arrow|Go forward|
|Down Arrow|Go backward|
|Right Arrow|Turn Right|
|Left Arrow|Turn Left|
|Red|Speed -1%|
|Green|Speed +1%|
|Yellow|Turn 90° left|
|Blue|Turn 180° left|
|Rew| (<<)|Speed -1%|
|Fwd (>>)|Speed +1%|
|Prew (\|<<)|Speed -10%|
|Next (>>\|)|Speed +10%|
|Info|Show actuall speed in %|
|Menu|Return to menu|
|Exit|Return to menu|
|Play|disable obstacle detection for 60 seconds|
|Stop|enable obstacle detection immediately|

#### Battery
Provide info on battery % and Voltage.
With Exit button, it returns you to Main Menu

#### Dice
Shake the Codey and you got random number from 1 to 6.
With Exit button, it returns you to Main Menu

### NEC Ir Decoder
Display the NEC Codes in format of Address:Command