# Geek OS 2.0.d

Small "OS" written in python for Codey Rocky.
MainMenu is controled via potentio meter(Volume) and buttons A, B, C
Functions assigned to buttons:
- A) Accept, confirm the choice
- B) Back, goes back to Sub Menu or Main menu
- C) Cancel, goes back to Main Menu

MainMenu
- IRDrive
- Battery
- DiceMenu
- NECIrDecoder
- LoudnessMonitor
- IrBadge

## IRDrive
Let you drive the Codey Rocky with Ir Remote Control. 
I use this [Emos](EmosIr.md)
You will need to find your Address and Commands, and update code accordingly to use your remote.
[Howto Set IR Remote Control](HowtoSetIRRC.md)
I use the Arrows, OK, Exit for basic navigation.

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
|Rew (<<)|Speed -1%|
|Fwd (>>)|Speed +1%|
|Prev (\|<<)|Speed -10%|
|Next (>>\|)|Speed +10%|
|Info|Show actuall speed in %|
|Menu|Return to menu|
|Exit|Return to menu|
|Play|disable obstacle detection for 60 seconds|
|Stop|enable obstacle detection immediately|

## Battery
Provides info on battery % and Voltage.

## Dice
Just shake the Codey and you got random number.
You can chose from several Dices:
- 6d 
- 10d 
- 20d
- 100d
- 2:6d


## NEC Ir Decoder
Display the NEC Codes in format of Address:Command

## LoudnessMonitor
Show loudness levels as graph on display.

## IrBadge
Show text on display. 4 chars are ok, otherwise it scrolls.
You can use [IrCodeyBadge](../LilyGo-T-Embed/scripts/READMEs/IrCodeyBadge.md) JS app for Bruce Firmware. 